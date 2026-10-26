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

   6. A filter over a nested collection that is absent is a retrieval failure, not an empty selection

   A filter at the top of a document selects the rule's subjects, and when the collection it runs over is absent, empty, or a bare key (`Resources:` with nothing after the colon, which YAML reads as null) the clause is reported as not applicable: `Resources[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b'` and `Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b'` over `{}`, `{"Resources":{}}` or `{"Resources":null}` report SKIP, the same as they do over a template whose only resource is a queue. A bare key reads as the empty collection at the population and as the absent key below it: `Tags[ Key == 'Env' ] exists` over a resource with a bare `Tags:` fails as it does over a resource with no `Tags` key. The block spelling of the selection, `Resources { this[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b' }`, and its `this.*[ ... ]` and `this[*][ ... ]` forms, read a bare `Resources:`, `Resources: {}` and `Resources: []` as the plain spelling does and report SKIP; the block is also an existence check on `Resources`, so over `{}` it reports FAIL where the plain spelling reports SKIP; a block nested in that block over a bare `this`, and a parameterized rule called with `this` from it, read the population as the block does. A wildcard, then a key, then a filter at the population, `Resources[*].Properties.Tags[ Key == 'Env' ] exists` or `Statement[*].Condition[ keys == 'x' ] exists`, reports SKIP over `{}`, `{"Resources":null}`, `{"Resources":{}}` and `{"Resources":[]}` alike; over the bare key and over the empty map it used to report FAIL on the key below. An alias of the population, `let r = Resources` then `%r.B.Properties.Tags[ Key == 'Env' ] exists`, reports FAIL over `{}` as the spelling without the alias does, where it used to report SKIP. A top-level list is a population too: a Terraform plan's `resource_changes[ type == 'aws_s3_bucket' ].change.after.acl == 'private'` reports SKIP when the plan has no `resource_changes` key, when the list is empty, and when its only change is an instance; a private bucket reports PASS and a public one FAIL. A variable bound to that list enumerates it: `let rc = resource_changes` then `%rc[ type == 'aws_s3_bucket' ].change.after.acl == 'private'` reports what the literal filter spelling reports over each of those plans (how a variable reads a list against a map is in [CLAUSES.md, "Filtering through a variable"](CLAUSES.md#filtering-through-a-variable)). That answer stops at the top level. A collection reached through other keys keeps the older behavior when it is absent: the query fails to retrieve, the clause's operator runs on the retrieval failure, and `==` reports FAIL while `not exists` and `empty` report PASS. Terraform's `planned_values.root_module.resources` and a Kubernetes manifest's `spec.template.spec.containers` sit below the top level, so they are affected. (A parameterized rule called as an assertion, `rule r { check(Resources) }`, reports SKIP on both documents, as `rule r when check(Resources) { ... }` does: the evaluator has no arm that fails a skipped rule closed for an asserting caller, so the caller reports what the invoked rule reports.)

   ```
   rule private {
       planned_values.root_module.resources[ type == 'aws_s3_bucket' ].values.acl == 'private'
   }
   ```

   Against a plan whose `root_module` has no `resources` key this reports FAIL, and the same rule with `not exists` or `empty` in place of `== 'private'` reports PASS. Against a plan with `"resources": []`, or whose only resource is an instance, all three report SKIP; a private bucket reports PASS and a public one FAIL. The same holds for `spec.template.spec.containers[ name == 'app' ].image == 'registry/app:1.0'` over a pod spec: no `containers` key FAIL (`not exists` PASS), an unrelated container SKIP, the app pinned PASS, the app on another image FAIL.

   Either spelling selects here: `resources[*][ type == 'aws_s3_bucket' ]` enumerates the list first and then evaluates its predicate against each element, so over a non-empty list it reports the same verdicts as the filter written directly on the collection; over an empty list the enumeration itself fails, so it reports FAIL where the bare spelling reports SKIP. A variable bound to such a list, with the filter written directly after it, reads as the bare filter: `let cs = spec.template.spec.containers` then `%cs[ name == 'app' ] exists` reports SKIP over `containers: []`, in both polarities and as a `when` gate, as `spec.template.spec.containers[ name == 'app' ] exists` does, and agrees with it over every other shape above; the authored wildcard spelled through the variable, `%cs[*][ name == 'app' ] exists`, reports FAIL over the empty list as `containers[*][ name == 'app' ] exists` does, and `%cs.name` reads as `containers[*].name`. A variable bound to an empty MAP reads the same way: `let cs = Resources.X.Properties.Containers` then `%cs[ name == 'app' ] exists` reports SKIP over `Containers: {}` in both polarities and as a `when` gate, as the literal filter does, where it used to report FAIL under `exists` and PASS under `!exists` on the empty enumeration; `%cs[*][ name == 'app' ]`, `%cs.*[ name == 'app' ]` and `%cs.name` over the empty map keep the enumeration's FAIL. One exception to "reads as the bare filter": a map-key filter written directly after the variable, `%cs[ keys == 'x' ]`, is the per-element reading over a list, not the bare filter's: over a populated list it reads as `containers[*][ keys == 'x' ]` (the elements that hold `x` are selected), over the empty list it is not applicable, where the bare `containers[ keys == 'x' ]` reads the list as the map to filter and is refused at any length ("Map Filter for keys was not a struct array"); over a map the two spellings agree.

   > **Workaround**: assign the filtered population to a variable and gate the rule on it, which is the same shape item 1 recommends for CloudFormation populations:

   ```
   let buckets = planned_values.root_module.resources[ type == 'aws_s3_bucket' ]

   rule private when %buckets !empty {
       %buckets.values.acl == 'private'
   }
   ```

   ```
   let app = spec.template.spec.containers[ name == 'app' ]

   rule pinned when %app !empty {
       %app.image == 'registry/app:1.0'
   }
   ```

   With the gate, a plan whose module has no `resources` key, an empty list, or only an instance reports SKIP, a private bucket PASS, and a public one FAIL; a pod with no `containers`, or only an unrelated container, reports SKIP, the app pinned PASS, and the app on another image FAIL.

7. `IN` and `NOT IN` against a query that enumerates a collection (`[*]`, `.*`, a filter, an enumerating
   `let` or interpolation) read the query as the list its results spell out, since 3.2. A rule that relied
   on the earlier per-result reading, where a string result was searched as text, can change verdict in
   either direction; the clauses that pass where they failed are listed, with the reason for each, under
   "Behavior change in 3.2: membership against an enumerating query" in [CLAUSES.md](CLAUSES.md).

8. A custom message body may not contain `<<`, and a line of a multi-line message body may not start with `>>`.

   A `<<` inside a message body is how a forgotten closing `>>` silently swallows the next clause: the next clause's own closing `>>` would close the first message, and the clause between the two tags would vanish from the parse tree without an error. Guard therefore refuses a message whose body holds `<<`. That excludes a body quoting a shell heredoc (`cat <<EOF`), a placeholder written as `<<your-bucket>>`, and a YAML merge key (`<<: *defaults`).

   A multi-line message ends at the first line that starts with `>>` after its indentation, and whatever follows that `>>` on the line is read as rule text. So a body line cannot start with `>>` either.

   A multi-line message body also may not hold a line that reads as a rule header at the start of the line (leading whitespace does not count): `rule <name>` followed by the end of the line, a `#` comment, a `(` parameter list, a `{`, or the word `when`. When the closing `>>` of a message is forgotten and a later rule happens to contain a line that is only `>>`, the first message would otherwise run across that rule's header and swallow the whole rule without an error; Guard therefore refuses a message whose body crosses a rule header. This is a heuristic over the body text, so a message that quotes a rule header verbatim at the start of a line, such as a "Fix: add a rule like" example, is refused where earlier releases read it as text. Prose such as `rule of thumb: ...` or `rule X whenever ...` is not a header.

   > **Workaround**: write the placeholder or merge key another way (`{your-bucket}`, `YOUR_BUCKET`, `merge: defaults`), quote a heredoc without its `<<`, start a body line with something other than `>>`, and move a quoted rule header off the start of its line (for example `e.g. rule encrypted {` or `| rule encrypted {`).

9. A comparison over an empty collection fails, in more places than the deprecation notice named.

   `Ports: []` under `Ports <= 100`, or `SecurityGroupIds: []` under `== "sg-1"`, used to pass: the
   operators compare a list's elements and an empty list has none, so nothing was compared and the clause
   passed. [Guard: Query and Filtering](QUERY_AND_FILTERING.md) lists an empty collection with a missing
   key as a retrieval error, and a retrieval error fails, so these comparisons now fail in both
   polarities, on every binary operator, `==`, `!=`, `<`, `<=`, `>`, `>=`, `IN` and `NOT IN`, with one
   exception: `==` and `!=` against a right-hand list compare the two lists as lists, so `[] == []` holds
   and `[] != [1]` passes. `IN` used
   to read an empty list as a subset of any set and pass, with `NOT IN` denying the nothing by negation
   and a string haystack skipped in both polarities; it is the same retrieval error there as elsewhere.

   The deprecation notice that announced this fired only when a clause as a whole compared nothing. Two
   cases now fail that the notice never warned about:

   - Per value, on either side. `Resources.*.Properties.Ports <= 100` over one resource with
     `Ports: []` and another with `Ports: [80]` compared the populated one and passed; the empty one now
     fails on its own, filed under its resource. The same holds with the empty collection on the right,
     as in `%expected == Resources.*.Properties.L` over an `L` of `[]`. Only a collection the document
     resolved to counts: a `[]` written in the rule, inline (`Mode == []`) or bound through `let`, is a
     value the author wrote and compares as one -- against a scalar the comparator refuses the kinds as
     it does for `[1]`, `[] == []` holds, and under `IN` it reads element-wise whatever the right side's kind, so `[] IN [80]` and `[] IN 80` are false while `[] NOT IN [80]` and `[] NOT IN 80` are true.
   - In a `when` condition. `when Resources.*.Properties.Ports <= 100 { ... }` opened its gate on the
     vacuous pass and enforced the body. The condition is now not satisfied by an empty collection, as
     it is not by a missing `Ports`, so the rule is reported not applicable and the body is not checked;
     the not-applicable summary names the empty collection ("the rule did not apply because one of its
     conditions was not met; a comparison it made reported: The value is an empty collection ..."). At
     rule level the condition is one conjunct over every selected value, so one resource's empty list
     leaves the whole rule not applicable even where a sibling's list is compliant; inside a
     per-resource block (`Resources.*[ Type == ... ] { when Properties.Ports <= 100 { ... } }`) the
     condition is decided per resource, and the body is enforced on the siblings whose lists hold.

   A filter predicate deselects: `Resources.*[ Properties.Ports <= 100 ]` leaves out a resource whose
   `Ports` is `[]`, as it leaves out one lacking `Ports`, and the clause decides on the resources that
   remain. A query that passes through an empty collection and resolves to nothing, such as
   `Tags[*].Key == 'x'` over `Tags: []`, is unresolved and leaves the rule not applicable with the
   unresolved reason rather than the empty-collection one.

   > **Workaround**: where an empty collection is expected and the body should still be checked, guard
   > the comparison with `<query> !empty` as a sibling condition, or check the collection in a
   > per-resource block so an empty one leaves only its own resource unchecked.

10. `empty` on a null value

   A null value is empty: `Properties.Foo empty` passes and `Properties.Foo !empty` fails when the template
   sets `Foo: null` or writes `Foo:` with nothing after the colon, which YAML reads as null. Those are the
   answers an absent `Foo` already gets, so a filter such as `Resources[ Properties.Foo !empty ]` deselects a
   resource whose `Foo` is null, and `when Properties.Foo !empty { .. }` means the rule does not apply.

   This is a verdict move. Earlier releases refused `empty` on a null with "Attempting EMPTY operation on type
   null that does not support it", and what that refusal did depended on where the filter stood. Heading a block,
   `Resources[ Properties.Foo !empty ] { .. }`, it stopped the run with that error at exit 255; as an access
   clause, `Resources[ Properties.Foo !empty ] !empty`, it failed the rule closed at exit 19, reported under
   "Could not be evaluated"; and as a `when` condition it failed its rule closed. Those were the engine declining
   to answer, not verdicts about the template. Now, for a template whose only such property is null, the block
   and the `when` form exit 0 because the rule does not apply, and the access-clause form still exits 19, this
   time because the selection is empty. A rule that relied on the refusal to flag a null needs to say so:
   `Properties.Foo exists` is true of a null and false of an absent key, and `Properties.Foo is_null` names the
   null itself.

11. <a name="filter-through-a-variable"></a> A filter through a variable that holds a map, `let m = Resources.WebServer` then `%m[ Metadata."AWS::CloudFormation::Authentication" exists ]`, walks the map's entries since 3.2, as the literal `Resources.WebServer[ Metadata."AWS::CloudFormation::Authentication" exists ]` always did.
   Before 3.2 Guard tested the map itself, so a predicate written against the map's own keys selected the map; since 3.2 it selects among the map's entries instead -- nothing, when none of them satisfies it or can be tested -- so a gate or an assertion over that selection moves with its operator and with what the query reads after the filter.
   On the selection itself, `empty` passes and `!empty` fails, while `exists`, `!exists` and a comparison are not applicable (`SKIP`); a key read BELOW a selection of nothing (`%m[ ... ].Key`, any depth) is not applicable under every operator, `empty` and `!empty` included, whether the map lacks the key, holds it with an empty value such as `Tags: []`, or holds it below further held keys.
   The verdicts that moved, by operator and by where the clause reads: the old verdict is the one the bound map's own answer gave, read against whether the path resolved on the map; the new one is the selection's.
   Measured on binaries built from the 3.1.12, 3.2.0 and 3.2.1 release commits (the commit the `3.1.12` tag names carries the manifest version `3.1.2` and its binary prints `cfn-guard 3.1.2`) and on this engine, except where a row says otherwise.

   | the clause | before 3.2 (the bound map tested as one value) | since 3.2 (the selection among the entries) | direction | measured on |
   |---|---|---|---|---|
   | `%m[ ... ] empty` (an assertion on the selection) | FAIL where the predicate held on the map | PASS (nothing selected) | a failure loosened | a static read of the 3.2.1 sources; this engine |
   | `%m[ ... ] !empty` | PASS | FAIL | fail-closed | a static read of the 3.2.1 sources; this engine |
   | `%m[ ... ] exists` | PASS | `SKIP` | a pass lost | the three tags and this engine |
   | `%m[ ... ] !exists` | FAIL | `SKIP` | a failure loosened | the three tags and this engine |
   | a comparison on the selection (`%m[ ... ] == x`) | decided on the map | `SKIP` | a failure loosened where it failed, a pass lost where it passed | the three tags and this engine |
   | `%m[ ... ].Key <op>`, a key read below the selection (any depth, every operator, `empty` and `!empty` included) | decided by whether the path resolved on the map | `SKIP` | a failure loosened where the path resolved and `!exists` or a comparison failed, where it resolved to a non-empty value and `empty` failed, or where it did not resolve (or resolved to an empty value) and `exists`, `!empty` or a comparison failed; a pass lost otherwise (`.Missing !exists` on a compliant template, PASS -> `SKIP`; `.Tags empty` over `Tags: []`, PASS -> `SKIP`) | a static read of the 3.2.1 sources; this engine |
   | `when %m[ ... ] empty { ... }` | the gate closed (the guarded rule `SKIP`) | the gate opens (the guarded rule runs) | fail-closed | a static read of the 3.2.1 sources; this engine |
   | every other `when` gate on the selection (`!empty`, `exists`, a comparison) or on a key below it | the gate applied | `SKIP` (the guarded rule `SKIP`, loosening a failure where the guarded rule used to fail) | a failure loosened | a static read of the 3.2.1 sources; this engine |
   | `rule a { %m[ ... ] empty }` then `rule b when a { ... }` | `a` FAIL, `b` `SKIP` | `a` PASS, `b` runs | fail-closed | the three tags and this engine |
   | `rule a { %m[ ... ] !empty }` then `rule b when !a { ... }` | `a` PASS, `b` `SKIP` | `a` FAIL, `b` runs | fail-closed | the three tags and this engine |
   | `let c = count(%m[ ... ])`: `%c >= 1`, `when %c == 0` | not measured: the releases did not parse `count(...)` as a clause head, and the `let c = count(...)` spelling was read on this engine only; a static read of the 3.2.1 release commit shows the whole map handed to the clause, which decided on the map's own keys | `count()` counts the entries kept, none over a selection of nothing: `%c >= 1` FAIL, `when %c == 0` opens | fail-closed | this engine |
   | `%p[ Name exists ].Name == 'b'`, where the filter kept `Inner` (which also carries `Name`) in the map's place (`let p = Resources.B.Properties`) | FAIL (the map's `Name` was `a`) | PASS (`Inner`'s is `b`) | the clause reads the kept entry where it read the map | the three tags and this engine |
   | `%p[ Name exists ].Tags exists`, the same map | FAIL (the map has no `Tags`) | FAIL on a different thing (neither the map nor `Inner` has `Tags`) | the same verdict, read of the kept entry | the same |
   | `Properties[ Foo !exists  this == 'b' ] !empty` after a key, over all-scalar properties `{ BucketName: b, Region: us-east-1 }` (the `this` clause keeps `BucketName`, which holds `Foo !exists` for want of any key) | PASS (every entry was handed to the predicate; `BucketName` was selected) | refused at exit 19 in both polarities (the scalar was kept through a vacuous absence; the text names the clause and the scalar, and asks the key of the map and the `this` clause of the entries apart) | fail-closed | this engine |

   Every move is in the fail-open direction (a failure loosened or a pass lost) except under an operator applied directly to the selection: `!empty` fails where it passed, the `when ... empty` gate opens, and a `when` gate on a named rule that asserts `empty` or `!empty` over the selection opens with that rule's moved verdict; an assertion over a selection compares the entries selected in the map's place.
   Where the filter kept an entry in the map's place rather than nothing, the clause reads that entry where it read the map, in both directions (the table's last two rows).
   A filter that kept nothing resolved and left an entry undecidable (a key filter in the predicate whose right-hand side does not resolve on that entry) is a selection of markers, not of nothing: the clause over it fails closed, and the notice says so instead of the fail-open sentence.
   The runtime notice names the moved selection and the direction and points here, by this item's anchor, for this table.
   A key filter applies to the map-valued entries of what it enumerates: a non-null scalar entry is passed over, neither selected nor reported, under every spelling (the alias, the literal `Key[ ... ]`, `.*`, `[*]`), with one split in what follows the pass-over: a Deployment `spec` with no `securityContext`, whose `replicas: 3` sits beside its sub-maps, opens `%s[ securityContext !exists ] !empty` on the sub-maps through `let s = spec` and is refused through the literal `spec[ securityContext !exists ] !empty`, the predicate holding on the `spec` itself (a `spec` that has `securityContext` opens the literal gate as the alias does);
   a filter after a key, or `this[ ... ]` in a block over the member, that passed a scalar over under a predicate that holds on the map read as one object is refused in both polarities, both when it kept nothing, whether or not a map-valued entry was tested and rejected (`spec[ securityContext !exists ]` over a `spec` holding `replicas: 3` alone;
   `Cfg[ Owner !exists ]` over `Cfg: { Mode: fast, A: { Owner: o }, B: { Owner: p } }`, whose sub-maps carry the key while `Mode` is passed over), and when it kept a map-valued entry in the map's place (`Statement[ Condition !exists ]` over a statement written as one object whose `Principal` is a map: the principal was selected where the statement should be, and a `when` gate over it opened on the wrong object), where a selection of nothing would pass `empty` and skip a gate that `spec[*][ securityContext !exists ]` and the list form fail;
   the refusal is a disagreement test, the predicate asked once, quietly, of the map as one object, so a predicate the map itself does not satisfy (`Enabled == true Owner !exists` over a map that lacks `Enabled`;
   `Owner !exists` over a map holding `Owner` beside a member that holds it) is not refused, the selection of nothing being the answer every spelling gives, a query-bound `%variable` is resolved quietly by the probe;
   only a name no scope binds, a rule reference or a call leaves the clause unread (`Cfg[ Owner !exists Kind == %k ]` over a map lacking `Kind` is not refused under `let k = Parameters.Kind` as it is not under `let k = 'k'`), with the readable clauses deciding, fail closed;
   the refusal defines `X` first and then names the remedy, `X[*][ ... ]` to read the map as one object where every candidate was a scalar and, where a map-valued entry was tested (read from the walk: a directive passed over or a null dropped beside the scalar is not one), `X.*[ ... ]` for the members and `X.Key !exists` for the map itself (`Cfg.*[ Owner !exists ] empty` passes over the two-sub-map `Cfg` above, both members carrying the key;
   `Cfg.Owner !exists` asks the map;
   `Cfg[*][ Owner !exists ]` is not named, since it reads the mixed map as one object and is refused again;
   `this.*[ ... ]` inside a block over the member);
   the two spellings of that filter read differently, and the asymmetry is the shipped reading: the literal `Cfg[ ... ]` is refused where the key spelling passed a scalar over, while the bound spelling `%c[ ... ]` (`let c = Cfg`) announces the moved selection instead and is read by its notice, a selection of nothing with the `DEPRECATION` notice of this item, `empty` passing and a `when ... !empty` gate `SKIP`, and `.*` reads the members, so over a map with no member its empty answer is the members reading, not a verdict lost;
   and that holds under a scalar passed over too: `spec.*[ securityContext !exists ]` over a `spec` of nothing but scalars lacking it selects nothing (`empty` passes, `!empty` fails, a gate on the selection stays closed), and over a `spec` whose `replicas: 3` sits beside its sub-maps keeps the sub-maps lacking the key, where 3.1.12 through 3.2.1 failed on the scalar with a retrieval error in both shapes (measured; the `security_context_absent_not_empty_after_dot_star` rows of the fixtures under `guard/resources/validate/wildcard-filter-release-verdicts/`) and the literal `spec[ securityContext !exists ]` over either map is refused;
   `.*` is never refused for a scalar it passed over, since the members reading is the one spelling admitted for the members of such a map;
   and a bound alias of a template section whose entries are all directives the walk passes over (`let r = Resources` with `%r[ Properties !exists ]` over a `Resources` holding only an `Fn::Transform`) announces the moved selection (nothing kept) where it was quiet;
   a predicate about the value itself (a bare `this` under any operator: `this == 'prod'`, `this !empty`, `this exists`, alone or beside a clause that names a key;
   `this !empty` and `this exists` count only as the whole predicate or an `or` arm of it) still tests a scalar entry, so `labels[ this !empty or env exists ] empty` over `labels: { team: '', tier: web }` keeps `web` through its `this` arm and fails as `labels[ this !empty ] empty` does, and one more disjunct never makes a filter select less (after a key or a `%name`;
   under `.*` and `[*]` a bare `this` that asks no more than `exists` or `empty` does not count, so `labels.*[ this empty or env exists ] empty` is enumerated as `labels.*[ env exists ] empty` is and passes, where `labels.*[ this !empty ] empty`, naming no key, is refused as an all-scalar map);
   a scalar so handed on and kept through a key absence it holds vacuously (`Properties[ Foo !exists or this !empty ] !empty` over an all-scalar `Properties`, which passed where `Properties[ Foo !exists ] !empty` is refused) is refused in both polarities, whatever the `this` clause beside the absence is and whatever it decided (`Foo !exists  this == 'b'`, `this != ''`, `this !is_list`), with the pass-over refusal's text naming the absence clause as written (`Tags.Env !exists`, a quoted key with its quotes) and the first scalar kept, and a remedy that asks the key of the map itself (`X.Key !exists`) and the `this` clause of the entries (`X[ ... ]` with no absence clause) apart, the members (`X.*[ ... ]` with no `this` clause) too where the map holds one, and the `this` clause named as a question of its own only where it asks more than `exists` or `empty` (`Cfg[ Owner !exists or this !empty ] !empty` is told to ask `X.Key !exists` of the map or `X.*[ ... ]` of the members, with no clause said to be left out);
   a `this !empty` or `this exists` conjunct beside other clauses (or the same by `not`: `not this empty`, `not this !exists`) hands no scalar over, since it decides nothing a non-empty scalar fails, while `this empty` and `this !exists` fail every non-empty scalar and are handed over as `this == 'x'` is, so `Properties[ this !empty  Foo !exists ] !empty` reads as `Properties[ Foo !exists ] !empty` does, and a scalar a deciding `this` clause keeps beside a vacuous key absence (`this == 'fast'  Owner !exists` over `{ Mode: fast }`) is refused as the rest are;
   a scalar the predicate's `this` clause REJECTED, beside members it rejected too, is refused where the map read as one object holds the predicate (`Cfg[ this !is_string  Owner !exists ] empty` over `{ Name: n, Sub: { Owner: o } }`: `Name` is handed over and rejected, `Sub` holds `Owner`, nothing is selected, and the map itself is no string and lacks `Owner`), since the selection of nothing and the one-object reading disagree as they do when the scalar was passed over (`Cfg[ this is_struct  Owner exists ] empty` over the same map keeps `Sub` and fails for real, unrefused); the remedy for a scalar so handed and rejected, beside a kept member or beside nothing, asks the key of the map (`X.Key !exists`) and the `this` clause of the entries (`X[ ... ]` with no absence clause) apart and never names `X[*][ ... ]`, which selects the map as one object on every template lacking the key; and the clause the kept-scalar sentence names is the KEY absence the scalar held vacuously, never a bare `this empty` or `this !exists` beside it (`labels[ this empty  owner !exists ]` over `{ team: '' }` names `owner !exists`);
   a scalar a POSITIVE type test rejected (`this is_struct`, `this is_string`, `this is_list`, `this is_bool`, `this is_int`, `this is_float`, `this is_null`, not negated) does not count toward that refusal or toward the member-kept one, since such a clause tells members from scalars on purpose: `Resources.B.Properties[ this is_struct  Tags !exists ] !empty` over `{ BucketName: b, VersioningConfiguration: { Status: Enabled }, LoggingConfiguration: { DestinationBucketName: logs } }` selects the two structs lacking `Tags`, passes, and fails under `empty`, with no refusal, and with `Tags` on both structs selects nothing (`!empty` fails, `empty` passes); a NEGATED type test (`this !is_string`) holds on a map too, so a scalar it rejects is counted;
   a map whose entries are all scalars, under a predicate that names a key the map itself holds, is refused through the variable as it is after a key (item 15's refusal);
   and a null entry, a bare key such as `B:` beside the resources, is handed to the predicate as the literal spelling hands it, under every spelling alike: an absence check holds on it, and an assertion over the selection then fails closed on the null member ("needed value at [null] was empty");
   a value check such as `Type == 'AWS::S3::Bucket'` fails on it and drops it, so the members beside it decide and `%r[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists` with `let r = Resources`, `Resources[*][ ... ]` and `Resources.*[ ... ]` pass over a bucket beside a bare key, as the literal `Resources[ ... ]` did in every release (observed `PASS` at exit 0 on binaries built from the release commits of 3.1.12, 3.2.0 and 3.2.1) and a type block did in 3.2.1 (observed `PASS`;
   3.1.12 and 3.2.0 refused a type block inside a rule at exit 255, "Unable to resolve type block query");
   the `.*` spelling failed there in those releases (observed: `FAIL`, then the released CloudFormation reporter panicked at exit 101, "internal error: entered unreachable code", before any failure text), while the `[*]` spelling was not applicable at exit 0 (observed in the released `--verbose` trees: the filter's predicate evaluated against the member produced by a `.*` before the wildcard that precedes the filter, or the document root when there is none (the document root here), so no null was reached under the value check;
   the fixtures under `guard/resources/validate/wildcard-filter-release-verdicts/` and the callout in [CLAUSES.md](CLAUSES.md) on a filter after `[*]` over a map of members), and the variable spelling was not applicable at exit 0 (observed: the trees test the bound `Resources` map as one value);
   under an ABSENCE check both of those spellings moved the other way: `Resources[*][ Tags !exists ] !empty` and `%r[ Tags !exists ] !empty` passed at exit 0 in every release (the predicate held on the document, or on the bound map, selected whole, the null never reached) and fail at exit 19 now, the null being a member the absence check holds on and the assertion fails closed on;
   over two buckets with no null the same rules pass in those releases and now alike (the fixture rows over `bucket_beside_a_null_entry.yaml` and over `two_buckets.yaml`), so the verdict there does not depend on the reading and that move is the null entry's, so the `.*` spelling alone moves off a failure from a release, while the `[*]` spelling moves off a selection of nothing (not applicable, `empty` passing) to a selection among the members, so `Resources[*][ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists` over that template moves from `SKIP` to `PASS` and `Resources[*][ Type == 'AWS::S3::Bucket' ] empty` from `PASS` to `FAIL` (measured: the releases read `SKIP` and `PASS`, the current engine `PASS` and `FAIL`), and the variable spelling moves off the bound map's own answer (the move its notice announces);
   over the list twin the `[*]` spelling was not applicable and the `.*` spelling failed in those releases where both pass now, so a list with a null element moved under those two spellings as well.
   A list-valued entry whose elements are all scalars (`L: [a, b]` beside the resources) is kept as a member and handed to the predicate as a map-valued entry is, selected by an absence check and dropped by a value check, where a scalar entry is passed over; the alternative reading, which would pass such a list over as a scalar is passed over, with the same exception for a predicate that compares the entry itself, is not the one shipped and is named here so that a change to the reading is deliberate.
   Guard writes a `DEPRECATION` notice to stderr for a filter whose selection moved this way, lost from the map or gained over an object's fields, naming the `let` and the filter's position; the verdict does not move.
   Runtime notices carry no provenance: this file records what each reading of a previous release rests on, a verdict observed on a binary built from the release's commit (the fixtures under `guard/resources/validate/wildcard-filter-release-verdicts/` and their README) or, where a sentence says so, a static read of its release commit, and a notice states the move alone.
   Whether a `%name` the filter's predicate reads is one value for the evaluation is read by following the `let`s its right-hand side reaches; the walk follows a chain of at most 16 `let`s, counted from the `let` bound to the document to the name itself. Only a name whose chain is longer is affected (`let a0 = Resources`, `let a1 = %a0`, ... `let a16 = %a15`: `%a15` is sixteen `let`s and is not affected; `%a16` is seventeen and is): it is read as the resource's, so a `when` over it is measured on every resource, the quiet probes keep nothing of it for the evaluation, and no quiet verdict is recorded for a filter that names it, so the notice fires where a record would have kept it quiet; one notice line per such name, written on the `DEPRECATION:` channel, names the `let` the rule read (`%a16`, not the `let` the walk happened to reach the bound on) and the 16-`let` bound, counted the same way, so the loss is said rather than silent; the line is written once per name per evaluation, however often the name is read, and a rule that reads two such names (`%a16` and a `%b20` on its own chain) gets a line for each. The answer is the same whichever name was asked about first, on the same chain or on another: a `let` inside the bound (`%a1`, `%a5`, a two-`let` chain beside the long one) stays one value for the evaluation after a longer chain was asked about, and the longer chain's name is nobody's binding after the shorter one was answered. Bind such a name closer to the document.

   The rule that decides the notice reads the map's entries.
   Two or more sub-maps are a collection only when they share a key name (`Type` on resources); a null entry and an empty-map entry (`B:` and `B: {}`, one empty resource spelled two ways) are passed over, and so is an entry under an intrinsic directive key beside the resources, any key with the `Fn::` prefix (`Fn::Transform`, an `AWS::Include` directive; a list-valued `Fn::ForEach::<Name>` under `AWS::LanguageExtensions`; a map-valued `Fn::ImportValue` written where a member would be), an instruction to the service and not a member, so a template that includes a snippet or loops over a list this way keeps the idiom quiet.
   The rule reads the prefix, not the one name `Fn::Transform`: no `Fn::` key names a resource, and the alternative, passing over `Fn::Transform` alone, would read a map with any other `Fn::` key beside its members as an object and announce it.
   The verdict reads the two spellings each by its own kind, the same in a map and in a list and under every spelling of the filter (`let r = Resources` then `%r[ ... ]`, the literal `Resources[ ... ]`, `Resources[*][ ... ]`, `Resources.*[ ... ]`): a null entry under a key filter is a member whose needed value is empty, so an absence check holds on it and an assertion over the selection fails closed on it at exit 19 ("needed value at [null] was empty"), while an empty-map entry holds an absence check and passes; under a value check (`Type == 'AWS::S3::Bucket'`) the null fails the predicate and is dropped, so the members beside it decide, where, observed on binaries built from the release commits of 3.1.12, 3.2.0 and 3.2.1 (the fixtures under `guard/resources/validate/wildcard-filter-release-verdicts/`), the `.*` spelling read `FAIL` and the released CloudFormation reporter then panicked at exit 101, the `[*]` and the variable spellings were not applicable at exit 0 (the filter's predicate evaluated against the member produced by a `.*` before the wildcard that precedes the filter, or the document root when there is none (the document root here), so no null was reached under the value check; the bound map tested as one value; under an absence check, `Resources[*][ Tags !exists ] !empty` and `%r[ Tags !exists ] !empty`, those two spellings passed in every release and fail now on the null member, the move recorded in the fixture rows over `bucket_beside_a_null_entry.yaml`), the literal passed in every release and a type block passed in 3.2.1 (3.1.12 and 3.2.0 refused it at exit 255), and over the list twin `[*]` was not applicable and `.*` failed the same way, so the list moved under those two spellings as well (item 11).
   On a collection, a pass held only by a key the map lacks is quiet when every entry is a map on which the predicate held, through a key it carries or for want of the key (`let r = Resources` with `%r[ Properties.Tags empty ]` over untagged buckets); under the population alias (`let r = Resources`, an alias chain, a parameter passed either) an entry that carries the key and fails the check is still a member, while under a variable the author named (`let p = Resources.LT.Properties`, a nested `let r = Template.Resources`) such a sub-map makes the map an object.
   On an object (a scalar entry, a sub-map carrying the checked key under a named binding, or sub-maps that share no key name) the lost selection is announced: the notice's own launch-template example, `%p[ TagSpecifications !exists ]` over a `LaunchTemplateData` sub-map that carries the key, where the `when ... !empty` gate is `SKIP` at exit 0 (observed on the fixture `tag_specifications_absent_gate_through_a_variable.guard` over `launch_template_with_tag_specifications.yaml`) where the released 3.2.1, which tested the bound map itself and found no `TagSpecifications` on `Properties`, selected it and opened the gate (inferred from that reading, whose test of a bound `Resources` map as one value the released `--verbose` trees show on the fixtures); the assertion form, `%p[ Tags !exists ] !empty` over all-scalar properties lacking `Tags`, fails at exit 19 now (observed on `tags_absent_not_empty_through_a_variable_bound_to_properties.guard` over `scalar_properties_without_tags.yaml`) where 3.2.1 passed it by the same reading (inferred).
   A selection gained over an object's fields is announced too, with the text naming the selection gained, when the predicate did not hold on the object because the object carries the checked key and every field selected held by lacking it.
   Quiet as before: a collection the predicate does not hold on (resources sharing `Type` under a `Type` the template lacks), an object over whose fields the filter selects nothing, and a positive predicate that selects the entry carrying what it asks for.

   The shapes that rule reads one way where the author may have meant the other, each pinned so a change to it is deliberate:
   - a nested collection under a named binding: `let r = Template.Resources` with `%r[ Properties.Tags empty ]` over a tagged bucket, or with `%r[ DeletionPolicy !exists ]` over a resource that carries the key, is announced although the author meant the resources, while the same rules file over a nested template that carries the key nowhere is quiet, so the template decides the notice; reading entries that all carry a scalar `Type` as a population whatever bound the map would quiet it and is not built, because the notice is a line at exit 0 and the verdict does not move with it;
   - a map of two or more sub-maps that lack the checked key and share some other key reads as a collection and stays quiet although the selection moved from the map to its sub-maps;
   - an object of sub-maps that share no key name is announced under any binding: `let d = Resources.LT.Properties.LaunchTemplateData` with `%d[ MetadataOptions !exists ]` over `Monitoring` and `IamInstanceProfile`, or `let s = spec` with `%s[ securityContext !exists ]` over a Kubernetes Deployment `spec` of `selector` and `template`; the same `spec` carrying a `securityContext` sub-map is the gained selection: the previous reading selected nothing, so `empty` passed and a `when !empty` gate was `SKIP`, where the walk now selects the three fields, `empty` fails and the gate opens;
   - one member beside an intrinsic directive, a `Resources` of `Fn::Transform` and `BucketA` alone, is not read by this rule at all (the notice is about a filter through a variable; the literal `Resources[*][ BucketA exists ]` over that map is refused, a limitation of item 15, where its two readings are recorded);
   - a map with no entry to read, empty, null-valued throughout or holding only empty-map entries (`Properties: {A: {}, B: {}}`, the JSON spelling of `A:` and `B:`, read the same way), is decided by the binding's shape alone, any single top-level key and not `Resources` by name: an empty top-level object (`let md = metadata` over a Kubernetes `metadata: {}`, or any `let x = Key` over an empty `Key:` at the document's top level) stays quiet although a `when` gate over `%md[ labels !exists ]` reports `SKIP` where it used to apply, and an empty nested collection (`let r = Template.Resources` over `Template.Resources: {}`) is announced although the same rule over a populated `Template.Resources` whose entries hold the check through a key they carry is quiet.
   - the announcing itself, against the literal's refusal: a filter through a variable over a map of sub-maps, under a predicate that names a key the map itself holds and holds on none of the entries (`let m = Resources.WebServer` then `%m[ Metadata."AWS::CloudFormation::Authentication" exists ]`, this entry's own example), selects nothing and passes at exit 0 with the notice, where the same filter written after the key, `Resources.WebServer[ Metadata."AWS::CloudFormation::Authentication" exists ]`, is refused at exit 19 (item 15's refusal). Whether the variable spelling should refuse as the literal does, or keep announcing for this release and refuse with the release that retires the notice, is tracked; the announcing reading stands.

   See [When the notice stays quiet](CLAUSES.md#when-the-notice-stays-quiet).

   The cells the tests pin for this rule, each clause as written over the shape of the map it ran on; a row marked unpinned is a spelling the text uses that no test asserts.
   The shape column uses the labels [CLAUSES.md](CLAUSES.md#one-object-wildcard) defines, `one-object`, `collection`, `mixed`, `all-scalar` (a map whose entries are all scalars) and `list` (a sequence rather than a map); a cell that reads otherwise describes the fixture in words (a bucket beside a null entry, a map of directives only, a mixed map read as one object), because the reading the row pins turns on that detail.

   | the clause | the map's shape | operator | verdict | notice | pinned by |
   |---|---|---|---|---|---|
   | `%m[ Metadata."AWS::CloudFormation::Authentication" exists ]` | one-object | let auth = %m[ ... ]; %auth exists / when %auth !empty / %auth...password !exists | SKIP | bound-map notice, 1: "did not select the map at /Resources/WebServer, which `let m = Resources.WebServer` held; it selected none of the map's entries." | tests/validate.rs:the_documented_filter_through_an_instance_binding_fails_open_and_is_announced, fixture `authentication_filtered_through_an_instance_binding.guard` |
   | `Resources.WebServer[ Metadata."AWS::CloudFormation::Authentication" exists ]` | one-object | n/a | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `%p[ Name exists ].Name == 'b'` | one-object | == | PASS | bound-map notice (moved down), one per site: "did not select the map at /Resources/B/Properties, which `let p = Resources.B.Properties` held; it selected one of the map's entries in its place." | tests/validate.rs:a_filter_whose_selection_moved_down_is_announced, fixture `filter_moved_down_to_an_entry.guard` |
   | `%p[ Name exists ].Tags exists` | one-object | exists | FAIL | bound-map notice (moved down) at "line:20,": "did not select the map at /Resources/B/Properties, which `let p = Resources.B.Properties` held; it selected one of the map's entries in its place." | tests/validate.rs:a_filter_whose_selection_moved_down_is_announced, fixture `filter_moved_down_to_an_entry.guard` |
   | `%s[ securityContext !exists ] !empty` | mixed | when gate !empty | gate opens on the sub-maps: rule FAIL over the spec lacking securityContext, PASS over the spec with it | bound-map notice: not asserted in the verdict fn | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling (cases "alias gate over a spec lacking securityContext", "alias gate over a spec with securityContext") |
   | `spec[ securityContext !exists ] !empty` | mixed | when gate !empty | FAIL | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling (case "literal gate over the same spec: refused, fail closed") |
   | `spec[ securityContext !exists ]` | mixed | when gate !empty | FAIL | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling (case "literal gate over the same spec: refused, fail closed") |
   | `Cfg[ Owner !exists ]` | mixed | empty | FAIL | none | eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence (case "the compliant mixed map, one member carrying the key") |
   | `Statement[ Condition !exists ]` | mixed | !empty; when gate !empty | FAIL | none | eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence |
   | `spec[*][ securityContext !exists ]` | mixed read as one object | !empty; empty | `!empty` PASS; `empty` FAIL (the selected object fails it) | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling (cases "the author's [*] over the spec lacking securityContext", "the author's [*] over the same spec under `empty`: the selected object fails it") |
   | `Cfg[ Owner !exists Kind == %k ]` | all-scalar | empty | PASS | none | eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence |
   | `Cfg.*[ Owner !exists ] empty` | mixed | empty | PASS | none | eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence |
   | `Cfg[*][ Owner !exists ]` | mixed | empty | FAIL | none | eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence |
   | `spec.*[ securityContext !exists ]` | all-scalar | !empty | FAIL | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling |
   | `spec.*[ securityContext !exists ]` | all-scalar | exists | SKIP | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling |
   | `spec.*[ securityContext !exists ]` | all-scalar | empty | PASS | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling |
   | `spec.*[ securityContext !exists ]` | all-scalar | when gate !empty | SKIP | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling |
   | `%r[ Properties !exists ]` | collection of directives only | empty | notice asserted, status not asserted | bound-map notice, 1, naming `let r = Resources` and /Resources | eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape (case "the population alias over a section written as a lone transform, under an absence check") |
   | `labels[ this !empty or env exists ] empty` | all-scalar | empty | FAIL | none | eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause |
   | `labels[ this !empty ] empty` | all-scalar | empty | FAIL | none | eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause (case "control: `this !empty` alone") |
   | `labels.*[ this empty or env exists ] empty` | all-scalar | empty | PASS | none | eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause |
   | `labels.*[ env exists ] empty` | all-scalar | empty | PASS | none | eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause (case "control: `labels.*[ env exists ] empty` over the all-scalar map") |
   | `labels.*[ this !empty ] empty` | all-scalar | empty | FAIL | none | eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause (case "control: `labels.*[ this !empty ] empty`") |
   | `Properties[ Foo !exists or this !empty ] !empty` | all-scalar | !empty | FAIL | none | eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence |
   | `Properties[ Foo !exists ] !empty` | all-scalar | !empty | FAIL | none | eval_tests.rs:a_clause_comparing_the_entry_itself_keeps_a_scalar_in_the_predicate_beside_a_key_clause (case "the literal spelling over all-scalar Properties under a key the map lacks") |
   | `Properties[ this !empty Foo !exists ] !empty` | all-scalar | !empty | FAIL | none | eval_tests.rs:a_key_filter_that_passed_its_scalars_over_and_kept_nothing_is_refused_where_it_could_hold_by_absence |
   | `%r[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists` | mixed | exists | PASS | none | eval_tests.rs:a_null_entry_fails_a_value_check_and_is_dropped_under_every_spelling (case "variable: the null fails the value check and is dropped; the bucket's name exists") |
   | `Resources[*][ Tags !exists ] !empty` | mixed | !empty | FAIL exit 19 over the null-entry documents (bucket_beside_a_null_entry.yaml and its list twin); PASS over two_buckets.yaml | not asserted by the cited test (the fixture README records the member notice over two_buckets.yaml and over bucket_beside_a_null_entry.yaml) | tests/validate.rs:a_null_entry_beside_a_bucket_draws_the_pinned_exit_code_under_every_spelling |
   | `%r[ Tags !exists ] !empty` | mixed | !empty | FAIL exit 19 | none | tests/validate.rs:a_null_entry_beside_a_bucket_draws_the_pinned_exit_code_under_every_spelling |
   | `Resources[*][ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists` | mixed | exists | PASS | none | eval_tests.rs:a_null_entry_fails_a_value_check_and_is_dropped_under_every_spelling (case "`[*]`: the null fails the value check and is dropped; the bucket's name exists") |
   | `Resources[*][ Type == 'AWS::S3::Bucket' ] empty` | mixed | empty | FAIL exit 19 | none | eval_tests.rs:a_null_entry_fails_a_value_check_and_is_dropped_under_every_spelling (case "`[*]`: `empty` fails on the bucket the value check kept") |
   | `Resources.*[ Tags !exists ] !empty`, `Resources[*][ Tags !exists ] !empty`, `%r[ Tags !exists ] !empty` over a document whose `Resources` holds `L: [a, b]` beside a tagged bucket | list | n/a | PASS | none | eval_tests.rs:a_list_entry_goes_to_the_wildcard_filters_predicate_under_every_spelling |
   | `%r[ Properties.Tags empty ]` | collection | empty | notice asserted, status not asserted | none | eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape (case "control: the population bound directly: no notice") |
   | `%p[ TagSpecifications !exists ]` | an object (the Properties map holds only the LaunchTemplateData sub-map) | when gate !empty | SKIP | bound-map notice, 1 per site, naming `let p = Resources.LT.Properties` and /Resources/LT/Properties (the ...) | eval_tests.rs:a_sub_map_carrying_the_checked_key_under_a_named_binding_is_announced (case "the example") |
   | `%p[ Tags !exists ] !empty` | all-scalar | !empty | not asserted (the cited test reads the notice only) | bound-map notice, 1: names `let p = Resources.MyBucket.Properties` and /Resources/MyBucket/Properties | eval_tests.rs:a_filter_through_a_single_map_binding_whose_absence_check_reached_into_the_map_is_announced (case "a one-key miss at the properties map's own first key") |
   | `%r[ DeletionPolicy !exists ]` | collection | !empty | notice asserted, status not asserted | bound-map notice naming `let r = Template.Resources` and /Template/Resources on the nested carrier | eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape (case "the common absence check over a nested collection one resource of which carries the key") |
   | `%d[ MetadataOptions !exists ]` | one-object | !empty | notice asserted, status not asserted | bound-map notice naming `let d = Resources.LT.Properties.LaunchTemplateData` and /Resources/LT/Properties/LaunchTemplateData | eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape (case "a named map whose sub-maps share no key name is an object") |
   | `%s[ securityContext !exists ]` | one-object | empty; when gate !empty | notice asserted, status not asserted | bound-map notice naming `let s = spec` and /spec (lost selection over selector+template) | eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape (cases "a Deployment `spec` of `selector` and `template`", "the same `spec` as a `when` gate") |
   | `Resources[*][ BucketA exists ]` | a bucket beside a null entry (FAIL under both polarities) | empty; !empty | FAIL | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (cases "a_map_with_a_null_entry_is_refused_under_its_own_key", "a_map_with_a_null_entry_is_refused_under_its_own_key_in_the_empty_polarity_too") |
   | `Resources[*][ BucketA exists ]` | mixed (a scalar entry beside a bucket) | empty; !empty | `empty` FAIL; `!empty` PASS | none | eval_tests.rs:a_bracket_wildcard_filter_naming_a_member_over_a_map_with_a_scalar_entry_tests_the_map |
   | `%md[ labels !exists ]` | all-scalar | when gate !empty | SKIP | bound-map notice naming `let md = metadata` and /metadata over the all-scalar map (1 notice) | eval_tests.rs:the_bound_map_filter_notice_is_quiet_on_a_uniform_collection_whatever_the_bindings_shape (case "a map of scalars: the predicate resolved no key on any entry") |
   | `Resources.*[ Metadata."AWS::CloudFormation::Authentication" exists ]` gating `%auth.Metadata."AWS::CloudFormation::Authentication".*.password !exists` | collection | when %auth !empty gate then %auth.Metadata."AWS::CloudFormation::Authentication".*.password !exists | FAIL | none | tests/validate.rs:the_documented_authentication_rewrites_check_the_resources_they_select, fixture `authentication_selected_from_the_resources.guard` |
   > **Migration**: test the map in the `when` condition (`when %m.Metadata."AWS::CloudFormation::Authentication" exists`), which checks only the instance the variable names, or bind a collection and filter that (`let auth = Resources.*[ Metadata."AWS::CloudFormation::Authentication" exists ]`), which checks every resource carrying the block, whatever its type. See [Guard: Clauses](CLAUSES.md#filtering-through-a-variable).

12. A decimal integer with a redundant leading zero is refused under an explicit `!!int` tag when YAML 1.1 and
    YAML 1.2 read it as different numbers

   `Mode: !!int 0755` is a bad value, reported as "Bad Value encountered parsing incoming file Value = !!int 0755,
   Loc = L:4,C:13: a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2; write 493 if octal 755
   was meant, or 755 if decimal was meant", and the file is refused the way `!!int abc` is. It is not read as the decimal 755. The same characters are octal 493 to a
   YAML 1.1 reader, which is what CloudFormation reads, and decimal 755 to a YAML 1.2 reader, which is what this
   loader reads, and a file mode or a netmask written that way almost certainly means 493, so there is no number
   the loader can pick that is not quietly wrong for one of them. The tag says the node is an integer; it does
   not say which radix the digits are in. The refusal is only for the spellings the two readers disagree on:
   `!!int 007` and `!!int 00` are 7 and 0 under both readings and load as those integers; `!!int 08` has a digit
   YAML 1.1's octal cannot hold, so 1.1 reads no integer there at all, and it is refused with that said. A sign
   is kept: `!!int -0755` offers -493 and -755. The message never names the `0o755` spelling, for the reason the
   workaround below gives. Every integer the message offers is one this loader reads back; a reading too wide
   for a 64-bit integer is named as such instead of offered. As a mapping key, `!!int 0755:` is refused with the
   same reason and the advice to write the integer that was meant as a quoted string, `"493"` or `"755"`, after
   which the tag can be dropped (a key is text, so the quoted integer is the key the author meant; dropping the
   tag alone would leave the key "0755", which is neither reading), and `!!int 007:` is the key `7`. An untagged
   `0755` is not affected and stays the string "0755".

   Earlier releases read `!!int 0755` as 755 with no diagnostic. A template that relied on that reading now
   fails to load.

   > **Workaround**: write the integer that was meant as a plain decimal, as the message says: `!!int 493` if
   > the octal was meant, `!!int 755` if the decimal was. The tag can then be dropped, since a plain `493` or
   > `755` is the same integer to every YAML reader. Do not write an untagged `0o755` in a template that
   > CloudFormation will read: it is 493 to this loader but a string to a YAML 1.1 reader.

13. A key filter's `==`, `!=`, `IN` and `NOT IN` against a list, a char range, or a list of ranges

   A map key is text, and a one-character key is compared with a char range by its character. `[ keys IN r[a,f] ]`
   selects the one-character keys the range covers and `[ keys NOT IN r[a,f] ]` the one-character keys it does
   not: over `Tags: { a: 1, b: 2, g: 3, y: 4 }` the first selects `a` and `b`, the second `g` and `y`, bare or
   written as `[r[a,f]]`. Earlier releases refused the pairing in both polarities, so `NOT IN r[a,f]` selected
   nothing. A key of more than one character is not a character: it is neither in a char range nor out of one,
   and `NOT IN` does not select it, because a pairing with no answer admits a key under neither polarity.

   That makes `NOT IN` against a char range a weak allowlist check. `Tags[ keys NOT IN r[a,f] ] empty` passes over
   `Tags: { a: 1, zz: 2 }`, and so does `Tags[ keys != [r[a,f]] ] empty`: `zz` is selected by neither polarity, the
   selection is empty, and nothing is reported about the key that was never compared. To require every key to be a
   single character in the range, match the key as text instead, `Tags[ keys != /^[a-f]$/ ] empty`, which selects
   `zz` and fails.

   `==` and `!=` against a bare range stay refused: `[ keys == r[a,f] ]` and `[ keys != r[a,f] ]` select nothing,
   since equality is not a question a range answers. Inside a list, equality is membership. A list on the right of
   `==` or `!=`, of any length, written out or bound through a variable (`keys == %names` over a one-element
   `names`), is read as a set, and so is a right-hand query that enumerates (`keys == %names[*]`, `keys ==
   Cfg.KeyList[*]`), whether it yields one value or ten: `[ keys == [r[a,f]] ]` selects the keys
   `[ keys IN r[a,f] ]` selects, `[ keys != [r[a,f]] ]` selects `g` and `y`, `[ keys == [r[a,f], r[x,z]] ]`
   selects `a`, `b` and `y`, and `[ keys == %names[*] ]` selects what `[ keys == %names ]` does over the same
   binding. Earlier releases read the number of values rather than the shape, so a one-element list, or an
   enumeration that reached one value, stayed strict equality and `[ keys == [r[a,f]] ]` selected nothing while
   `[ keys == [r[a,f], r[x,z]] ]` selected the covered keys; adding or removing an element now changes which values
   are in the set and nothing else.

   **A string on the right is a value the key is equal to, not text the key is contained in.** Earlier releases
   read a string right-hand value of `IN` and `NOT IN`, and of a `==` or `!=` widened over two or more right-hand
   values, as text the key could be contained in: `Tags[ keys IN 'Environment' ] exists` passed over the key
   `Env`, `Tags[ keys NOT IN 'aws:cloudformation:stack-name' ] empty` passed over the key `aws:cloudformation`,
   and `let allowed = Allowed[*]` then `Tags[ keys IN %allowed ]` over `Allowed: ['Environment', 'Owner']`
   selected every key that was a substring of one of them. A string is now equal to a string, under every
   comparator and however it arrived (a bare string, a `let`-bound string, a binding over an enumerating query
   of strings), so the first clause is `SKIP` (the filter
   selects nothing), the second `FAIL` (the key is selected), and a key named by a substring of a right-hand
   string is not selected. A list literal never read as containment: it arrived as one value whose elements were
   compared by equality, so `[ keys IN ['Environment'] ]` selected `Environment` and nothing else before and does
   now, and plain string lists keep their selection under `==` and `!=` with only the report moving, as below.
   Guard writes a `DEPRECATION` notice to stderr, once per filter site, for a key whose selection moved this way,
   naming the key, the string it is contained in, the site and the operator as written; the verdict does not
   move. To select the keys a string contains, match the key as text: `Tags[ keys == /^aws:cloudformation/ ]`.

   **A negated key filter over two or more right-hand values selects a key that differs from every value.** Earlier
   releases folded `NOT IN`, and a `!=` widened over two or more right-hand values, as ANY: a key equal to one value
   was selected because another value differed from it. So `let exempt = Mappings.Exempt.Names[*]` then
   `Resources[ keys NOT IN %exempt ].Properties.Encrypted == true` over `Names: [BucketA, BucketB]` selected
   `BucketA` and `BucketB` and checked the exempt buckets, and `let reserved = Mappings.Reserved.Keys[*]` then
   `Tags[ keys NOT IN %reserved ] == 'ok'` over `Keys: [Owner, CostCenter]` checked the reserved tags. The fold is
   ALL now, so an exempt bucket is exempt and a reserved tag is left out: with an unencrypted exempt bucket the
   first rule moves from FAIL to PASS beside an encrypted sibling and from FAIL to SKIP when the exempt buckets are
   the only resources, and the second from FAIL to PASS. The same move happens through `.*` over a map of names,
   through `!=` over the same binding, and through a binding that resolves to two or more LISTS (`let exempt =
   Mappings.*.Names` over `Names: [BucketA]` and `Names: [BucketB, BucketD]`): earlier releases selected a key held by
   one list because the other list did not hold it, and the ALL fold leaves it out. A list holds a key when one of its
   elements is EQUAL to it, then as now, so `Names: [BucketA]` beside `Names: [BucketALogs]` is the same move
   (`BucketALogs` is another name, not a string that contains the key), and a list whose elements only contain the
   key holds it under neither fold. A list literal, bound (`let exempt = ['BucketA', 'BucketB']`) or inline, never
   folded as ANY, because it arrived as one value whose elements were compared by equality, a single right-hand value
   folds the same either way, and `IN` is ANY under both; none of those moves. Earlier releases read "differs from"
   as "does not contain" for a STRING value, so a key equal to one value and contained in every other
   (`['Env', 'Environment']` with the key `Env`, or any prefix-shaped list of strings) was left out then as now and
   does not move either. Guard writes a `DEPRECATION` notice to stderr, once per filter site, for a key whose
   selection moved this way, naming the key, the right-hand values that hold it, the right-hand values that selected
   it before (a string that does not contain it, a list with no element equal to it; a list is written as the rule
   language writes one, `['BucketB', 'BucketD']`), the site and the operator as written; the verdict does not move. To
   leave a key out by name, this is the reading; to select the keys that differ from one particular value, write that
   value alone on the right.

   **What changes in the reports for a list on the right.** This applies to every `[ keys == [...] ]` and
   `[ keys != [...] ]`, plain string lists included, not only to char ranges; for string lists on the right of
   `==` and `!=` the selection is the same as before and only the report moves. The report describes the operator
   as written, with one record per failing key, whatever the length of the list:

   - In the JSON and structured output (`-o json`, `-o yaml`, `--structured`, junit and sarif), the record type
     stays `InResolved` and its `to` array still carries the whole list. Its `comparison` value changes from
     `["In", false]` to `["Eq", false]` for a written `==`, and from `["In", true]` to `["Eq", true]` for a
     written `!=`. Its `error_message` reads "is not equal to any of [...]" for `==` and "is equal to [x], one of
     [...]" for `!=`, where `x` is the element the key was equal to; it read "was not present in [...]" for both.
   - The summary line reads "provided value [k] is not equal to any of [...]" for `==` and "provided value [k] is
     equal to [x], one of [...]" for `!=`; it read "did not match expected value in [...]" and "did match expected
     value in [...]".
   - The verbose tree (`-v`) prints `Comparison= EQUALS` or `Comparison= not EQUALS` where it printed `IN` and
     `not IN`; the record kind, `GuardClauseInBinaryCheck`, and its `to` list are unchanged.
   - `IN` and `NOT IN` against a list are unchanged in every output (against a string on the right the selection
     itself moves, as the paragraph above says), with one exception: a key whose comparison never had an answer. A right-hand value the query could not reach (`keys != %denied` where `%denied` is
     `Resources.*.Properties.Name` and one resource has no `Name`) and a pairing the comparator refuses
     (`keys == [r[a,f]]` over a two-character key, under either polarity) both read "could not be compared with
     expected value in [...]" in the summary line, and "could not be compared with [...]. Error = [reason]" in the
     JSON and structured `error_message`, under `IN`, `NOT IN`, `==` and `!=` alike; the reason names the value or
     the pairing. These read "did not match expected value in" and "was not present in" before, which assert an
     answer the comparison did not have. A `==` or `!=` against a single value is unchanged as well: one
     `Resolved` record with `"Eq"`, as always.
   - The legacy resolver, which no command reaches, reads a bare binding name as the values it holds and not as the
     query it was assigned from, so `keys == %spread` with `let spread = %one[*]` is a set in the live engine and a
     single value there. Known drift, carried as a row in both parity tables.

14. `parse-tree` prints a `%variable` query part as `Variable`, where it printed `Key: '%name'`

   The parser reads a `%name` in a query into a query part of its own ("fix(parser): parse a %variable to its
   own query part"). Before that change a variable was a `Key` whose text kept the `%`, and the evaluator read
   the prefix to tell the two apart, so a quoted key that happened to begin with `%` -- `."%foo"` or `["%foo"]`
   -- produced the same `Key("%foo")` and was interpolated as the variable `foo`, exiting 5 with "Could not
   resolve variable by name foo across scopes". A `Key` is now always the key it spells, and a variable is a
   `Variable`.

   Rendered queries, the `Context=` lines of the verbose output, and every message that names a query are
   unchanged: the `%` is written back in them. What moves is the parse tree, which serializes the part by its
   variant. For a rule that reads `%type`, `parse-tree` wrote

   ```yaml
   - Key: '%type'
   ```

   and, with `--print-json`, `"Key": "%type"`; it writes

   ```yaml
   - Variable: type
   ```

   and `"Variable": "type"`, the name without its `%`. The parts around it, the query's `match_all`, the
   clause's comparator and location, are printed as before.

   A consumer of the parse tree that reads a `Key` whose text begins with `%` as a variable reference no
   longer sees one from this release, and does not recognize the `Variable` part it sees instead. To read trees
   from both releases, treat a `Variable: name` part as the variable `%name`, and a `Key` beginning with `%`
   from an earlier release the same way; from this release on, a `Key` beginning with `%` is a literal key the
   rule quoted, and is to be read as the key it spells.

   > **Workaround**: none is needed for rules, which parse and evaluate as before. A tool that consumes
   > `parse-tree` output accepts both spellings as above.
15. <a name="filter-after-a-wildcard-over-a-map-holding-the-key"></a> A filter straight after `[*]` or `.*` over a map that holds the predicate's key itself while none of
   its map-valued entries holds it is refused in both polarities when the map has no scalar entry. The
   shape that matters is an IAM `Statement` written as one object whose every field is an intrinsic or a
   list, `{ Effect: !If [...], Action: ['*'], Resource: ['*'] }`: by its shape it is a collection (a
   `Statement` with a plain `Effect` string is one object and is handed to the filter whole), and nothing
   in the document says which it is. The released 3.2.1, measured on a binary built from its release commit over a one-object
   statement with scalar fields, asked the filter's predicate of the resource that holds the statement
   and passed `Statement[*][ Effect == 'Allow' Action == '*' ] empty` at exit 0 there and over the
   one-element-list twin alike (the all-intrinsic statement itself was not among the measured documents); it fails now in both forms. The cost is every clause the list form passes, in either polarity,
   since the refusal reads neither the operator nor the value: `Statement[*][ Action == '*' ] !empty`
   fails the one-object statement by the same refusal where the list form passes; `Statement[*][ Effect
   == 'Allow' ] empty` over a restrictive one-object statement (`Effect: !If [...]`, `Action:
   ['s3:GetObject']`) fails it where the list form passes, because `Effect` is a key of the statement
   itself and no field of it holds the key; and a projecting binding read with the author's own `[*]`
   before the filter, `when %b[*][ AssumeRolePolicyDocument exists ] !empty` over `let b = Resources.*[
   Type == 'AWS::IAM::Role' ].Properties`, is refused and fails its gated rule at exit 19 over a compliant
   role whose `Properties` holds only maps and lists, where it passed before. A rule written any of these
   ways disagrees between the two shapes. The filter does run over the map's entries first, and is
   refused unless it kept some entry through a clause that resolved a key of that entry: `Resources[*][
   Type == 'AWS::S3::Bucket' or BucketA exists ]` keeps the bucket on its `Type` and is decided on it,
   where `Rules[*][ R1 !exists or Action == 'deny' ]` keeps the `R1` member by the `R1` miss alone and
   is refused although the member holds `Action`, and so is `Rules[*][ R1 !exists or Action IN %allowed ]`
   with `let allowed = ['deny']`, as `Action IN ['deny']` is. The grounding re-run reads a `%variable`
   some scope binds (a `let` bound to a literal, the lookup-table shape `let allowed = ['deny']`; a `let`
   bound to a query or a call, `let allowed = Mappings.Allowed.Actions[*]`; a filter's capture; a
   parameter) and a function call whose arguments stay inside the entry (`M[ keys ==
   to_upper(Tags[ Key == 'Env' ].Value) ] !empty` over an entry holding those tags) as it reads the inline
   spelling, so `Rules[*][ R1 !exists or Action IN %allowed ] !empty` with `let allowed = ['allow']` keeps
   the member on `Action` and passes, and `Cfg[*][ Mode exists or M[ keys == to_upper(Tags[ Key == 'Env'
   ].Value) ] !empty ] !empty` keeps the entry whose `M` the key filter selected from. The re-run is a
   quiet reading: a binding no clause has resolved yet is resolved for it with nothing recorded and its
   memo taken back when the clause's read ends, so the verdict is the same whether or not a clause
   before the filter, an earlier rule or an earlier entry's real run read the binding first, and
   whatever order the map's entries come in; the re-run enters that reading
   only for a clause that names a `%variable` or calls a function, and a binding it resolves is kept for
   the length of one enumeration, so a map of fifty entries reads `%denied` once, not fifty times. A `%variable`-rooted query
   grounds nothing, wherever its values lie: `%actions !empty` with `let actions =
   Resources.A.Properties.Rules.R1.Action` resolves a value below the `R1` entry and still does not
   anchor it, since no clause of the entry resolved it; a block run over the binding's values,
   `%actions { this == 'allow' }` or `%t { Value == 'prod' }` over a filter's capture, grounds nothing
   the same way, its `this` reading the binding and not the entry, and so does a filter over the binding's
   values whatever the operator inside it, `%t[ Value exists ] !empty` as `%t[ Value == 'prod' ] !empty`
   (unary and binary clauses alike, `%t[ Value !exists ] empty` and `%t[ Missing !exists ] !empty`
   included, and a key filter over a literal's map, `%cfg[ keys == 'PROD' ] !empty`). A disjunct the re-run cannot answer without
   evaluating through the scope outside the entry -- a rule reference or call, a `%variable` no scope
   binds -- is left unread and never grounds the entry, so an entry kept through such a disjunct alone is
   refused as one kept by a miss alone is (write the check after the filter, or over a key the entry
   holds). A function argument the entry's filtered map lacks is not read under the re-run, neither
   beside the entry nor from the document: the in-map miss stands, and the clause, read on the re-run's
   terms rather than the real run's, counts for nothing, neither grounding the entry nor failing it. So
   an entry the real run kept through a document-level value is grounded only by another conjunct that
   resolved a key of the entry: `Cfg[*][ Mode !exists  Kind == 'k'  this[ keys == to_upper(Tags[ Key ==
   'Env' ].Value) ] !empty ] !empty` with `Tags` at the document root alone keeps `B` grounded by
   `Kind`, where the same filter without `Kind == 'k'` leaves `B` ungrounded and refused; and an entry whose
   own value differs from the document's (`Tags: prod` on the entry, `dev` at the root) is not grounded
   through a disjunct the real run itself failed. A disjunction
   the re-run reads only in part, a readable clause that fails beside an unread one, counts for nothing
   rather than against the kept entry, since the real run kept the entry through the clause left unread.
   An entry the predicate cannot decide beside one it held without grounding (an `A` whose `Tags` is a
   string beside a `B` held by a miss alone, `Ref !exists` over a `B` that has no `Ref`) fails the clause
   closed on the undecided entry's marker alone, under `some` and in a `when` gate as well, so `some
   Cfg[*][ Mode exists or M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty or Ref !exists ].Kind
   == 'k'` fails as the same rule over a decided `A` is refused. The filter's capture (`Cfg[*][ x | ... ]`)
   holds what the clause answers with, in the order the loop met the entries: with nothing grounded and
   an entry undecided, `let sel = Cfg[*][ x | Mode exists or M[ keys == to_upper(Tags[ Key == 'Env'
   ].Value) ] !empty or Ref !exists ]` leaves `%x` holding the undecided entry's marker alone, carrying
   the own-key advice the selection's markers carry, so `some Cfg.%x.Kind == 'k'` fails closed as `some
   %sel.Kind == 'k'` does; an entry that grounds the enumeration leaves the capture holding every held
   entry's key and every undecided entry's marker; a refused enumeration leaves it holding one marker
   that carries the refusal's sentence, so a sibling
   clause of the same rule that reads `%x` after the refused clause (`Cfg[*][ x | ... ] !empty or
   Cfg.Fallback exists  some Cfg.%x.Kind == 'k'`) fails closed on the refusal, which is held at its own
   clause while the rule goes on; inside a predicate (`Resources.*[ Properties.Cfg[*][ x | R1 !exists ]
   !empty ]`) the refusal is a marker the outer filter fails closed on, and the capture forwarded up out
   of the predicate holds that marker alone. A unary operator (`!empty`, `empty`, `exists`, `!exists`)
   over a selection that holds an undecidable entry beside a decided one hands the marker up at the
   first undecidable entry, whatever the decided sibling reads (the error it hands up names the LATEST-MINTED
   refusal among the entries from the raising one on, its text and token together, when any of them is a
   refusal's marker, so two refused maps in one selection name the one met second in either order, else the
   first undecidable entry's own reason; earlier versions raised the first undecidable entry's error alone, so
   a budget marker met before a refusal's marker left the predicate's entry plain and the reversed selection left it refused), so `when Resources.*[ Properties.M[ keys
   == to_upper(Tags[ Key == 'Env' ].Value) ] !empty ] !empty` and its `exists` and `!exists` twins fail
   their rule closed at exit 19 over an entry whose `Tags` is a string beside one whose `Tags` is a list
   of pairs, the same gate under a comparison the decided entry passes (`.Type == 'Y'`) fails closed
   too, while under a comparison the decided entry fails (`.Type == 'X'`) the gate is settled by that
   decided failure and the rule is not applicable at exit 0, the one place the unary reading and the
   comparison's part (the rows of
   `the_hand_up_reading_of_an_undecidable_value_inside_a_unary_filter_is_pinned` in `eval_tests.rs`
   are the record; the latest-minted reading over two refused maps, in either order, has its own record
   (pinned by `eval_tests.rs:a_unary_operator_over_two_refusals_raises_the_later_minted_pair_in_both_orders` and `eval_tests.rs:two_refusals_minted_inside_one_run_fold_to_the_later_minted_pair_in_both_orders`)). The wildcard's own capture (`Cfg[ y ][ x | ... ]`) is the
   enumeration, not the selection: every key the wildcard enumerated when some entry grounded it
   (`[Mode, A, B]`, as `Cfg[ y ][ Kind == 'k' ]` reads it) and the markers alone otherwise. Both
   captures are bound as the rest of the query is walked under the held entries, entry by entry in the
   map's order, each entry in its own scope (a later part that reads the scope's root, `.M[ keys ==
   to_upper(Env) ]`, reads the entry's `Env`), so a later part of the same query that reads a capture
   sees the keys met so far, on the own-key path exactly as on the regular path (no own key named by the
   predicate), which binds each key and walks that entry at once: `Cfg[*][ x | Mode exists or Kind ==
   'k' ].Peers[ this IN %x ]` and `Cfg[ y ][ x | Mode exists or Kind == 'k' ].Peers[ this IN %y ]` each
   select `[A, B]` over `A.Peers: [A, B]`, `B.Peers: [B, Z]`, the regular spelling's selection (`Z` is
   never read against a bound `B`). So the selection's content follows the map's key order on both paths:
   the same filter over `B.Peers: [B, Z]` written before `A.Peers: [A, B]` selects `[B, A, B]`. And a
   held entry met before an entry the predicate cannot decide is walked before that entry's marker is
   bound, so its read of the capture sees no marker and the marker follows in the selection, where the
   same entries in the other order read the marker first and the read fails closed on it. Binding every
   key of the loop before any walk was considered and is not taken: the capture frames' per-entry
   contract (a capture an entry's predicate makes is that entry's alone, and a later part reads the keys
   held so far) is the reading, and a bind-first order would give each entry's continuation the other
   entries' keys. That walk runs
   under the clause's own flag, not the predicate's, so a
   refusal in it (`.Tags[*][ Key == 'Env' ]` over a held entry whose `Tags` is a map holding a non-scalar
   entry, since a map of scalar tags is decided by its `{ Key, Value }` list twin and refuses nothing there,
   or `.Sub[*][ s | R1 !exists ]` over a map whose own key the predicate names) is raised at the top level of a rule and
   held at the clause, and inside a predicate it is a marker the outer filter fails closed on. A
   refusal met by that walk, raised or as such a marker, under the own-key spelling, under the regular
   spelling (`Cfg[*][ x | Kind == 'k' ].Sub[*][ s | R1 !exists ]`, `Cfg[ x | ... ]`) and inside a
   predicate alike, and under a filter after a key, over a list's members or over a projected binding
   (`%r[ b | ... ]`) as under a wildcard, cuts each capture the clause bound back to what it held before
   the clause's walk began and gives it the refusal's marker, standing where the placement rule below puts
   it and carrying the refusal's own sentence, and the clause binds no further key, so a sibling clause reading
   `%x` or `%y` (`... !empty or Cfg.Fallback exists  some Cfg.%x.Kind == 'k'`) fails closed as the clause
   reading the selection does; a refusal under one resource of `Resources.*.Properties.Cfg[*][ x | ... ]`
   takes the keys bound under the earlier resources with it (one clause around the whole walk, its mark
   taken before the loop), where one under the second resource's predicate run of `Resources.*[
   Properties.Cfg[*][ x | ... ] ... ]` cuts that run's keys alone and leaves the first resource's: each
   run is its own clause and marks for itself, and a refusal MINTED inside a predicate's run, at any depth
   (the block spelling's fold, the key spelling one level down, a fold re-raised by an inner predicate's
   `!empty`, a fold in a rule the run calls), marks that run's entry refused and cuts the entry's
   captures, read off the refusal token the ending raise carries against the count the run opened at,
   where a marker that carries no token (a key filter's own undecidable, a regular expression out of
   budget, and a refusal that reaches a key filter's right-hand side as a query with no answer on the
   data: `M[ keys == Tags[ Key == 'Env' ].Value ]` over a `Tags` that is a string is refused there as
   unevaluatable, which carries no token, so the filter's marker for the map carries none; pinned by `eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one`)
   leaves the entry plain with its captures. The same side refused by a comparison the engine abandoned,
   `M[ keys IN Allowed[*].Type ]` over an `Allowed` whose own key names a member, arrives with its token
   and marks the entry (pinned by `eval_tests.rs:a_plain_marker_carrying_a_refusals_sentence_is_a_refused_read_inside_a_predicate_run`);
   where two refusals meet in one fold the later-minted one is the one
   the raise names, reason and token together, so a refusal minted inside the run marks the entry
   whichever order the values were met in; a plain marker left by an inner run over a refusal minted
   before that run opened still carries the token for the enclosing run, which marks its own entry by it
   where the refusal was minted inside it; a refusal minted while a file-level binding is resolved marks
   no entry's run: the binding's query runs once, inside whichever predicate run read it first, and that
   run's entry reads the memoized marker as every later reader does, so two entries over one binding read
   one kind in either resource order (a `let` owned by a block built inside the run, or a called rule's
   body, is the run's own and marks its entry). A refusal minted in a query's TAIL, outside a predicate,
   after the predicate decided an entry (`let sel = Resources[ x | Type exists ].Properties.M[ keys IN
   Allowed[*].Type ]`), marks no entry and cuts no capture: `%x` keeps the entry and `some
   Resources.%x.Type == 'T'` passes,
   the refusal standing in `%sel`'s own value, registered where it was raised (unmeasured on the releases:
   no fixture row holds a key filter refused in a selection's tail, so the baseline is this evaluator's
   reading before the change, which cut the capture for a refusal the predicate never met;
   pinned by `eval_tests.rs:a_refusal_minted_inside_a_walk_cuts_the_loops_captures_whatever_marker_carries_it`). A continuation that refuses its own capture (`.Rules[0][ r |
   ... ]`, a capture after an index over a map) is such a refusal inside a predicate as it is outside
   one. What another clause of the block filed
   under the same name before the clause (`Cfg[ x | Kind == 'k' ] !empty` ahead of the refused `Cfg[*][ x
   | ... ].Sub[*][ ... ]`) stands below the cut, and `some Cfg.%x.Kind == 'k'` passes on those keys beside
   the marker. A marker the walk meets for another reason, a key filter under one entry whose right-hand
   side does not resolve (`.M[ keys == Names[*].Name ]` under an entry with no `Names`), is no refusal of
   the continuation: the selection keeps that entry's siblings and so do the captures. A capture the
   clause first meets after the cut (`Groups.*.Rules.*[ r | ... ]` with `G1.Rules` refused before any
   member bound `r`, whether or not a later entry reaches `r`) holds the refusal's marker as the cut
   captures do, and the marker a reader sees stands at one place by one rule. A refusal a filter after
   `[*]` or `.*` raises stands at the map that was refused (`/Resources/R/Properties/Cfg` for an own-key
   `Cfg` refused under `Resources.*`, not the `.*` entry the loop held), whether a loop of the query is
   above it, none is, or a predicate's query delivers the refusal as a marker, so the path a reporter
   surfaces is the map the text names. A refusal that names no map (a continuation refusing its own
   capture, `.Rules[0][ r | ... ]`, or any other error the walk raises) stands at the entry whose walk
   refused (`/Resources/R/Properties/Cfg/A` for that continuation under `Cfg[ x | ... ]`). Every capture
   the refused part of the
   query declares holds that marker, one a later filter declares included
   (`Cfg[*][ x | R1 !exists ].Sub[ s | ... ] !empty or Cfg.Fallback exists` leaves `%s` holding it at the
   root as under a wildcard), so a sibling reading `%s` fails closed. When a `when`
   is read again to decide whether its answer moved, the cut and the marker are what the real run
   writes, so the measured reading of `%x` is the real run's reading. The own-key enumeration runs every entry's predicate
   before it walks the first held entry, so the verbose and structured reports list all of a filter's
   predicate records (`Filter/Map#N`) and then the records of the walks under its held entries, where a
   filter whose predicate names no own key of the map lists each entry's predicate record and then that
   entry's walk; a later entry's predicate error (an unresolved `%name` in a disjunct) ends the run
   before an earlier entry's walk is refused; and when nothing grounds the enumeration no held entry's
   continuation is walked, so no record or notice of that continuation appears. 3.2.1 has no own-key
   enumeration, so none of this is measured against it. A capture read bare (`%x == 1`) carries
   the marker with nothing left of its query (the capturing loop's own walk is not the read's), and the
   console prints that as
   `NoAnswerError` at the
   entry's path with the filter's reason, where the same marker read through a `let` (`let v =
   Cfg[*].M[ keys == ... ].Sub` as `%v`) keeps the binding's unwalked parts and prints as
   `RequiredPropertyError` with them as the missing property; the marker's kind itself is not on the
   console line. The other reading, a capture that keeps every
   held entry's key whatever the branch, is recorded here as the alternative;
   `Statement[*][ Action !exists ] !empty` over the all-intrinsic statement keeps every field value only
   because none can carry `Action` and is refused, where its list form fails the clause. The refusal
   names the spellings that read one object and a list of them alike, and, where the key's value is
   itself a map and the map's sub-maps share a key name, after the path the `.*` spellings that read each
   member's own key, for the author who
   meant the members; over the all-intrinsic statement, whose `Action` is a list, that sentence is left
   out, since those spellings read nothing there; see [Guard: Clauses](CLAUSES.md). A map of member maps
   that share a key name, one of them named like the
   key, is not this case: the key names a member, and the filter is the selection the author wrote. An
   entry under an intrinsic directive key beside the members (`Fn::Transform` with its `Name` and
   `Parameters`, or any other `Fn::` key) is not a member and is passed over by that reading too, so
   `Resources[*][ BucketA exists ] empty` over a `Resources` of a transform beside `BucketA` and `TableC`
   is the selection the author wrote and passes (nothing selected), where `!empty` fails. That selection
   dates from the shared-key test passing the transform over (before that, counted as a member whose
   keys shared nothing with its siblings, the transform made the map an object and the key was refused in
   both polarities); passing the directive over where the members are counted moves two other shapes.
   One resource beside a transform is a map of one member, which cannot be told from the one object, so
   `Resources[*][ BucketA exists ] empty` over `Fn::Transform` beside `BucketA` alone is refused in both
   polarities. And a directive
   whose value is not a plain member map, the list under `Fn::ForEach::<Name>` or a one-key intrinsic map
   (`Fn::ImportValue: { Fn::Sub: ... }`), no longer breaks the collection beside it, so the same filter
   over `BucketA` and `TableC` beside one passes `empty` and fails `!empty` where both polarities were
   refused. The other reading of the directive (passing over `Fn::Transform` alone and counting every other
   `Fn::` key as a member) is recorded with the notice's rule in item 11; the one-member shape, with its
   other reading, is the limitation below. A predicate that names the directive key itself,
   `Resources[*][ "Fn::Transform" exists ]` and the `.*` spelling alike (the two wildcards read the map's
   own key through one test), asks about a key of the map and no member, so it is refused in both
   polarities (write `Resources."Fn::Transform" exists` to ask the map for its directive), where each
   read the transform's `{ Name, Parameters }` as a member named like the key, selected nothing and passed
   `empty` over a template that includes a snippet. And the walk itself, under every spelling of the
   filter (`Resources[ f ]`, `%r[ f ]` over `let r = Resources`, `Resources[*][ f ]`, `Resources.*[ f ]`
   and the block's `this[ f ]`), passes a directive over under a predicate about the members, whatever its
   value (a predicate on the entry itself is the exception below): the transform's map, the `Fn::ForEach::<Name>` list and a map-valued
   `Fn::ImportValue` beside the members are neither selected nor read, so `Resources[ Properties.Tags
   !exists ].Type exists` and `Resources[*][ BucketA !exists ].Type exists` pass over a template that
   includes a snippet, where the absence check used to hold on the directive's map and select it, failing
   `.Type exists` on it. That
   moves the tagging idiom over a template whose every bucket is tagged beside a transform: `let r =
   Resources` with `%r[ Properties.Tags empty ] !empty` fails there, as it does with no transform, where it
   passed by selecting the transform. The directive is handed to the predicate where the predicate names
   a key the directive's value holds, a rule about the directive itself: `Resources.*[ Name ==
   'AWS::Include' ].Parameters.Location == /^s3:\/\/approved-bucket\//`, and `when Resources[ Name ==
   'AWS::Include' ] !empty { ... }`, find the include beside a bucket as they find it alone, so an
   unapproved snippet fails (`Resources."Fn::Transform".Parameters.Location == ...` names the include by
   its key and never depended on the walk). A lone `Fn::ForEach::<Name>` is passed over at any depth:
   under `AWS::LanguageExtensions` the loop writes keys into the map that holds it (its output key carries
   the identifier) and is never a value in its own right, so an SSM parameter's `Tags` map written as a
   loop, `Tags: { 'Fn::ForEach::Tags': [...] }` under `Tags[*][ Key !exists ] empty`, and `States: {
   'Fn::ForEach::Steps': [...] }` under `States[*][ Type !exists ] empty` select nothing and pass, as
   `Resources.*[ Properties.Tags !exists ] empty` passes over a `Resources` holding only a loop. A lone
   `Fn::Transform` is passed over at a template section only, the section read by the map's path: its LAST
   segment is one of the six map-valued sections where CloudFormation lets a section-level directive stand
   (`Resources`, `Outputs`, `Conditions`, `Mappings`, `Metadata`, `Rules`) and NO segment above it is one of
   the six, so a section is a direct child of a template root or of a wrapper around a template: a template
   nested below a key (`Template.Resources[ ... ]`) and a template in a list (`Templates[*].Resources[ ... ]`)
   read as the root does, and a section reached through a variable (`let r = Resources`, `let r =
   Template.Resources`) is the section, while a map named like a section anywhere inside a section's content
   is content, not a section: a resource's `Metadata` attribute written through an include
   (`Resources.*.Metadata[ Comment !exists ] empty` fails over it), a nested stack's `Properties.Parameters`,
   a backup selection's `Conditions`, a custom resource's `Properties.Outputs` and a resource whose logical
   id is `Outputs` each hold a lone transform as a value's whole content, handed to the predicate.
   `Parameters` is not among the six: a lone `Fn::Transform` is the value wherever it stands except at a
   section, where it stands for the section's content, so under `Parameters` it is handed to the predicate
   and `Parameters[ Value !exists ] empty` fails over it, while a lone `Fn::ForEach::<Name>` there is a loop
   as anywhere, its expansion being the parameters, and `Parameters[ Type !exists ] empty` passes over it;
   that pair of verdicts over `Parameters` is the documented reading. One limit of reading the name by
   position: a rules-file literal's sub-map named like a section
   is read as one (`let lit = { Resources: { 'Fn::Transform': {...} } }` then `%lit.Resources[ ... ]`: a
   literal is built on the root path, so its `Resources` has the path `/Resources`), the
   document-provenance question the notice's quiet record answers and this rule does not. A directive's
   reading is decided by its own key and position, never by the kind of an unrelated sibling: at a section
   every `Fn::` key is a directive, beside the members or alone; below a section only a loop is, and every
   other `Fn::` key there is a value, so `Properties: { 'Fn::Transform': {...}, BucketName: 'b' }` and the
   same include beside `BucketName` and a `VersioningConfiguration` map read the same, and
   `Resources.*.Properties.*[ Status !exists ] empty` fails over both (the include lacks `Status`; one added
   compliant property moves nothing), as `[ Tags !exists ] empty` fails over the include alone; by the
   static read of its release commit 3.2.1 handed the include on in every one of these shapes, so they are unchanged
   from the release. Below a section a lone `Fn::Transform` is a value's whole content and is handed on
   like a lone `{ 'Fn::If': [...] }`: `SecurityGroupIngress: { 'Fn::Transform': {...} }` under
   `SecurityGroupIngress[*][ Description !exists ] empty` and `Tags: { 'Fn::Transform': {...} }` under
   `Tags[*][ Value !exists ] empty` (the `.*` and key-filter spellings alike) fail, the absence check holding
   on the transform's map. By a
   static read of its release commit, 3.2.1 had no directive test and handed every lone directive to the predicate:
   the transform-written ingress failed there as it does here (unchanged from the release), while a
   directive-only section and a lone loop below a section pass here where the absence check held on the
   directive there, a FAIL -> PASS move against the release by that read, unmeasured against a built
   release. A predicate on the entry itself reads a directive as its value, as it reads a scalar: `this
   IS_LIST`, `this == %loop` and `this IN [...]` select the `Fn::ForEach::<Name>` list, so `Resources.*[ this
   IS_LIST ] empty` fails over a section holding a loop (the fail-closed direction; by the static read of its
   tag 3.2.1 handed the list on there too, so this shape is unchanged from the release); a predicate on the
   members passes the directive over, and so do `this exists` and `this empty`, which ask only whether the
   entry is there. The bound-map notice reads a map by the shape rule, which leaves
   every `Fn::` key out of the population: a map holding a directive alone (`SecurityGroupIngress: {
   'Fn::Transform': {...} }`, a property written as a map-valued `Fn::ImportValue`, a one-key `Fn::If`
   list) is a map nothing was read from and is decided by the binding as an empty map is, so under a
   named binding (`let ing = Resources.SG.Properties.SecurityGroupIngress`, `let p =
   Resources.Bucket.Properties.LoggingConfiguration`) the filter is announced once per site, while the
   walk still hands the lone directive to the predicate and the verdict does not move. The
   resources an include or a loop produces are not in the template and are not checked: Guard reads the
   template as written, before the service expands it. A VALUE
   intrinsic as a value's only key, `{ 'Fn::If': [...] }` as a property's whole value, is the author's own
   wildcard target and is read as it was: the conditional list
   is handed to the predicate, so `SecurityGroupIngress[*][ Description !exists ] empty` and
   `Tags.*[ Key !exists ] empty` fail over it (the absence check holds on the list and selects it), as
   does `Target[*][ Name !exists ] empty` over a `{ 'Fn::FindInMap': [...] }` value. Shape and
   selection are different questions: the shape read (object or collection, which decides the own-key
   refusal and the bound-map notice) leaves every `Fn::` key out of the population it compares, wherever
   the map stands, while the selection below a section hands every non-loop `Fn::` key to the predicate.
   So a `Mappings.RegionMap` holding a transform beside `us-east-1: { AMI }` and `us-west-2: { AMI }` is
   the collection of those two (`RegionMap[*][ "us-east-1" exists ]` is the selection the author wrote,
   not the own-key refusal; `let m = Mappings.RegionMap` with `%m[ ImageId !exists ]` prints no notice, the
   two region entries holding the absence check as members, where `%m[ AMI !exists ]` is announced under
   that named binding whatever sits beside them, every entry carrying the key the author checked absent),
   and
   `Mappings.RegionMap.*[ AMI !exists ] empty` FAILS over the same mapping, the transform lacking `AMI`,
   where the previous reading passed a directive beside map-valued members over and the clause passed: a
   PASS -> FAIL move in the fail-closed direction (an include whose content Guard cannot read is selected
   and reported, not passed over). At a section every `Fn::` key is passed over, a lone value intrinsic
   among them: `Resources: { 'Fn::ImportValue': ... }` under `Resources.*[ Properties.Tags !exists ]
   empty` selects nothing and passes where the previous reading handed the import on and the absence
   check held on it, a FAIL -> PASS move over a template the service does not accept (invalid
   CloudFormation, low severity), recorded here and not reversed: reversing it would read a lone
   `Fn::ImportValue`, `Fn::If` or `Fn::Sub` at a section as a member for a reading that is not
   CloudFormation either way. Over
   a template with a parameter literally named `Default` and no parameter declaring one,
   `Parameters.*[ Default !exists ] !empty` ("the parameters that declare no default") keeps every
   parameter and passes, and `Parameters.*[ Default exists ] empty` passes, the parameter named `Default`
   tested like the others; `Resources[*][ BucketA !exists ] !empty` keeps every resource and passes, and
   `Resources[*][ BucketA exists ] empty` over a map of resources keeps nothing and passes, the silent
   answer the own-key reading was first written against, accepted for a map that is nothing but members
   (`Resources.BucketA exists` asks about the resource by name); after `[*]` Guard writes a `DEPRECATION`
   notice to stderr once per such site where the selection moved against the released reading, naming
   the key and the member. That reading is measured, on binaries built from the 3.1.12, 3.2.0 and 3.2.1
   tags, which agree: a filter straight after `[*]` over a map of members asked its predicate of the
   value the query stood at before the wildcard (the document for `Resources[*]` and for a keyed
   `Resources.F.Properties.Tags[*]`; the resource for `Resources.*.Properties.Tags[*]` and for the same
   query inside a type block; the block's value for `Resources { this[*][ ... ] }`; the bound map itself
   for `%r[*]` with `let r = Resources`), and selected that value whole where the predicate held on it,
   nothing where it did not. So `BucketA exists` found no `BucketA` on the document, `empty` passed and
   `!empty` failed as they do now, nothing moved and nothing is announced; `BucketA !exists` held on the
   document, which that release selected whole where this one selects every member, a move the notice
   states; and a key the document holds that no member holds moved the same way and is announced too:
   `Resources[*][ AWSTemplateFormatVersion exists ] !empty` passed in those releases and fails now,
   `.Type == 'AWS::S3::Bucket'` after it failed and is not applicable now, and `Resources.*.Properties.
   Tags[*][ Type exists ] !empty` over a map-shaped `Tags` passed on the resource's `Type` and fails
   now. A predicate that fails on that value and keeps no member (`Resources[*][ BucketA exists Type ==
   'AWS::S3::Bucket' ] empty`) selected nothing under both readings and is not announced. A predicate
   that held on that value only by the ABSENCE of a key it lacks (`Resources[*][ Tags !exists ]` over a
   document with no top-level `Tags`) selected the value whole and now selects the members that lack
   the key; it is announced too, the notice naming the absent key as the author wrote it and the number
   of members the enumeration keeps ("keeps 2 of them", "keeps none of them" where every member holds
   the key), since `empty` and `!empty` agree between that release's reading and this one's only while some member is kept, and a
   continuation moves either way (`Resources[*][ Tags !exists ].Type == 'AWS::S3::Bucket'` failed in
   those releases on the document's missing `Type` and passes now on the members'; this notice named
   that shape a limit of the release before it announced it). A
   predicate that fails on that value and leaves a member undecidable (`Resources[*][ BucketA !exists  M[
   keys == Tags[ Key == 'Env' ].Value ] !empty ] empty` over a member whose `Tags` is a string) is
   announced, since the selection moved from no member to an undecidable member; the notice says that
   and nothing of the verdict, which the clause's operator and its siblings settle (`empty` passed over
   the selection of nothing and fails on the marker, `!empty` failed and fails, a continuation such as
   `.Type == 'x'` was not applicable and fails, a `some` sibling or a `when` gate may settle past the
   marker). A clause that compares against a function call, names a variable or refers to another rule is
   not asked of that value, since it cannot be asked quietly: the predicate's other clauses decide
   whether it held there, and a predicate made only of such clauses is taken as having held. In a
   disjunction (`Type == 'AWS::Lambda::Function' or Properties.Public == %flag`) a clause that fails on
   that value beside such an unread clause is taken as having held through it, so the notice goes out;
   where the hold rests on a clause Guard cannot read against that value (it names a variable, function
   or rule), the notice is decided after the members are read: a member kept or left undecidable is a
   move whatever the previous release selected (that value, or nothing), so the notice states it, from
   that value to the members the enumeration keeps or to an undecidable member; where nothing is kept the notice says the
   selection may have moved and names that clause, the one the disjunction it took as held was taken as
   held through, so a line for a move that did not happen (the unread clause would have failed too) reads
   as the guess it is, where a hold read in full is stated as a move. The clause is named as the author
   wrote it, whatever its kind: an access clause, a block (`"a\tb" { let v = Public %v == true }`, the key
   quoted as the grammar reads it, a tab in it escaped, a literal's inner spaces kept), a `when` block (its
   condition an access clause, a reference to another rule or a parameterized call), a reference to another
   rule, or a parameterized call with its arguments; a body's clauses are spelled the same way, a
   parameterized call or a nested block among them included. One shape has no spelling of its own and is
   named by the record tree's re-print: an argument, condition or body whose filter predicate itself holds a
   block, a `when` block or a rule reference, whose filter prints as the `(filter-clauses)` placeholder
   (`chk(Resources (filter-clauses))`); the text still names the clause, in the tree's words rather than the
   author's. Such a predicate never records
   a quiet verdict: a parameterized rule whose filter compares against its parameter is announced on every
   call whose selection moved, never silenced by an earlier call that kept nothing. The verdict does not
   move with the notice, and no release refused the filter. After `.*` over a map there is no notice: 3.2.1
   enumerated the entries there as this one does (over a list, `.*` then a filter read the member produced
   by the nearest earlier `.*` in the releases and moved, the README's 3.2 bullet on `.*` over a list; no
   notice marks that move). Members are the same kind of thing,
   which Guard reads as a key name every one of them carries (`Type` on `BucketA` and `TableC`). That
   reading has a limit the notice exists for: two sub-maps that share a key name by coincidence have the
   key structure of two resources, so they are read as members too. A `Metadata` holding
   `AWS::CloudFormation::Init: { config: ... }` beside `cfn-lint: { config: ... }` under
   `Resources.*.Metadata[*][ "AWS::CloudFormation::Init" exists ] empty` selects nothing and passes over a
   template that declares Init, as do a bucket's `Properties` of `LifecycleConfiguration: { Rules }`
   beside `ReplicationConfiguration: { Role, Rules }`, a container's `resources` of `limits` and `requests`
   sharing `cpu` and `memory` under `resources[*][ limits exists ] empty`, and a launch template's
   `Monitoring: { Enabled }` beside `EnclaveOptions: { Enabled }`; no shape of the keys tells them from
   `BucketA: { Type, Properties }` beside `TableC: { Type, Properties }`, so Guard does not refuse them;
   after `[*]` it writes the `DEPRECATION` notice naming the key and the member, with the spelling that
   asks the map for its member by name (`Metadata."AWS::CloudFormation::Init" exists`, `resources.limits
   exists`), which is the check those rules meant. After `.*` the same coincidence shapes select among
   the sub-maps and pass with NO signal of any kind: `Resources.*.Metadata.*[ "AWS::CloudFormation::Init"
   exists ] empty` over a template that declares Init passes at exit 0 with nothing on stderr, a limit of
   this release; 3.2.1 enumerated them the same way, so nothing moved there for a notice to record, while
   the sibling shapes whose sub-maps share no key name (`Init` beside `Authentication`) are refused aloud
   under `.*`; a `.*` warning for the coincidence shapes is not written, so a reader of `.*` rules has
   only this entry. For these shapes the member reading agrees with the shipped release under `[*]`:
   the released 3.1.12, 3.2.0 and 3.2.1 binaries (measured) asked `"AWS::CloudFormation::Init" exists`
   of the resource above `Metadata`, which does not hold it, selected nothing and passed `empty` over a
   template that declares Init, as this release does at exit 0; nothing moved there, so nothing is
   announced for the member's name (as for `Resources[*][ BucketA exists ] empty` over a template
   declaring `BucketA`). What
   does move for these shapes, and is announced, is a key the value before the wildcard holds and no
   sub-map holds: `Resources.*.Metadata[*][ Type exists ] !empty` held on the resource's `Type`, passed
   in those releases and fails now. The member reading is kept because it is what the author of a
   selection among members wrote, and the notice names the rewrite at the site. Three readings were on offer: the
   member reading with the notice, which this release keeps; a refusal whenever the only key-naming
   clause names a member's id, which would refuse the two-resources map as well until a discriminator
   the key structure does not hold is found; and keeping the shipped whole-map verdict for exactly this
   shape under `[*]` while announcing it, which keeps the FAIL but reads a selection among members as a
   question about the map. This release ships the first; the other two are named here as the
   alternatives, so that a change to the reading is deliberate. Sub-maps that share no key name are the fields of one
   object, so the key stays the map's own and the refusal applies: a resource's `Metadata` holding
   `AWS::CloudFormation::Init: { config: ... }` beside
   `AWS::CloudFormation::Authentication: { S3AccessCreds: ... }` under `Resources.*.Metadata[*][
   "AWS::CloudFormation::Authentication" exists ] empty` is refused in both polarities, as the same
   `Metadata` holding only the `AWS::CloudFormation::Authentication` block is, and so is a bucket's
   `Properties` written as all sub-maps, `BucketEncryption: {
   ServerSideEncryptionConfiguration: [...] }` beside `VersioningConfiguration: { Status: Enabled }`,
   under `Properties[*][ BucketEncryption exists ]`, as the literal and as `let p = Resources.*[ Type ==
   'AWS::S3::Bucket' ].Properties` with `%p[*][ BucketEncryption exists ] !empty` (which had gone from
   refused to `SKIP` with its body never checked). A list or an intrinsic call under the key (`Action:
   ['*']`, `Effect: !If [...]`), or a null or an empty map (`B:` or `B: {}`, one empty resource spelled two
   ways, read alike) beside the members, keeps the own-key reading and its
   refusal. `Parameters[*] { Default !exists }` and `Parameters[*].Default` hand the map on
   whole, the array-or-single reading of `[*]` over a map, and ask whether a parameter named `Default`
   exists; `Parameters.*.Default !exists` and `Parameters.* { Default !exists }` read the members.

   One member beside an intrinsic directive, a `Resources` of `Fn::Transform` and `BucketA` alone: with the
   directive passed over, the map holds one member, which has nothing to be like, so the own-key reading
   `Resources[*][ BucketA exists ]` is refused in both polarities, as it is over a one-entry map; the other
   reading, counting the directive toward the two entries, reads the lone resource as a member and selects
   nothing, so `empty` passes. The refusal is the reading built. Which of the two readings is wanted is
   open.

   The cells the tests pin for this rule, each clause as written over the shape of the map it ran on; a row marked unpinned is a spelling the text uses that no test asserts.
   The shape column uses the labels [CLAUSES.md](CLAUSES.md#one-object-wildcard) defines (`one-object`, `collection`, `mixed`, `all-scalar`, `list`) and four of this section's own: `directive`, a map whose entries are `Fn::` keys alone (a lone `Fn::Transform`, a loop), `beside a member` when such a map sits among the members; `all-intrinsic`, a one-object statement whose entries are all intrinsic maps or lists (an `Fn::If` `Effect` beside list-valued `Action` and `Resource`); `collection by shape, own-key arm`, a map the shape test reads as a collection and the own-key refusal arm then reads; and `n/a`, a row whose clause fixes no map shape (a binding, or a spelling refused before it reads one). `top-level rule` marks a row whose verdict is the rule's, not one clause's.

   | the clause | the map's shape | operator | verdict | notice | pinned by |
   |---|---|---|---|---|---|
   | `Statement[*][ Effect == 'Allow' Action == '*' ] empty` | all-scalar | empty | FAIL | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "one_object_violating_empty") |
   | `Statement[*][ Action == '*' ] !empty` | one-object | !empty | FAIL | own-key refusal text "`[*]` then no kept entry holds a key the predicate names", "`Key` is `Action`, a key of ... | eval_tests.rs:a_wildcard_filter_over_a_mixed_or_dot_enumerated_one_object_map_is_refused_by_name (case "bracket wildcard over the all-intrinsic one-object statement under !empty: the same refusal") |
   | `Statement[*][ Effect == 'Allow' ] empty` | all-intrinsic (Effect an `Fn::If` map, Action and Resource lists) | empty | FAIL | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "an_all_intrinsic_one_object_statement_is_refused_comparing_its_map_valued_key_empty") |
   | `when %b[*][ AssumeRolePolicyDocument exists ] !empty` | collection by shape | when gate over !empty | REFUSED exit 19 | none | tests/validate.rs:a_filter_with_an_authored_star_over_a_projecting_binding_is_refused_by_name_and_not_announced, fixture `filter_with_an_authored_star_on_a_projecting_binding.guard` |
   | `when %b[*][ AssumeRolePolicyDocument exists ] !empty` under `let b = Resources.*[ Type == 'AWS::IAM::Role' ].Properties` | n/a | n/a | REFUSED exit 19 | none | tests/validate.rs:a_filter_with_an_authored_star_over_a_projecting_binding_is_refused_by_name_and_not_announced, fixture `filter_with_an_authored_star_on_a_projecting_binding.guard` |
   | `Resources[*][ Type == 'AWS::S3::Bucket' or BucketA exists ]` | collection | !empty | PASS | member-move notice (1 notice asserted) | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "bracket wildcard, a member key beside the map's own key") |
   | `Rules[*][ R1 !exists or Action == 'deny' ]` | collection by shape, own-key arm | !empty | REFUSED | own-key refusal text "then no kept entry holds a key the predicate names" | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "a disjunct that never holds beside the negated own key") |
   | `Rules[*][ R1 !exists or Action IN %allowed ]` | collection by shape, own-key arm | !empty and empty | FAIL | own-key refusal text (refused true on the deny rows) | eval_tests.rs:an_own_key_grounding_probe_does_not_reach_outside_the_entry (cases "a_disjunct_reading_a_literal_variable_is_read_and_fails_on_every_entry", "a_disjunct_reading_a_literal_variable_is_read_under_empty_too") |
   | `Resources.A.Properties.Rules[*][ R1 !exists or Action IN %allowed ] !empty` and its `] empty` twin under `let allowed = ['deny']` | n/a | n/a | REFUSED | own-key refusal text | eval_tests.rs:an_own_key_grounding_probe_does_not_reach_outside_the_entry (cases "a_disjunct_reading_a_literal_variable_is_read_and_fails_on_every_entry", "a_disjunct_reading_a_literal_variable_is_read_under_empty_too") |
   | `Action IN ['deny']` | n/a | IN | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `Resources.A.Properties.Rules[*][ R1 !exists or Action IN %allowed ] !empty` under the query-bound `let allowed = Mappings.Allowed.Actions[*]` | n/a | n/a | PASS | none | eval_tests.rs:the_grounding_probe_is_a_quiet_reading_independent_of_what_ran_first (case "a_query_bound_let_no_clause_resolved_is_read_and_leaves_no_memo") |
   | `M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty` | collection | !empty inside the own-key predicate | PASS | none | eval_tests.rs:an_entry_the_predicate_could_not_decide_is_not_refused_as_a_filter_that_selected_nothing (case "the own-key arm after [*]") |
   | `Rules[*][ R1 !exists or Action IN %allowed ] !empty` | collection by shape, own-key arm | !empty | PASS | none | eval_tests.rs:an_own_key_grounding_probe_does_not_reach_outside_the_entry (case "a_disjunct_reading_a_literal_variable_that_holds_grounds_the_entry") |
   | `Resources.A.Properties.Rules[*][ R1 !exists or Action IN %allowed ] !empty` under `let allowed = ['allow']` | n/a | n/a | PASS | none | eval_tests.rs:an_own_key_grounding_probe_does_not_reach_outside_the_entry (case "a_disjunct_reading_a_literal_variable_that_holds_grounds_the_entry") |
   | `Cfg[*][ Mode exists or M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty ] !empty` | collection | !empty | PASS | none | eval_tests.rs:an_entry_the_predicate_could_not_decide_is_not_refused_as_a_filter_that_selected_nothing |
   | `Resources.A.Properties.Rules[*][ R1 !exists or %t[ Value exists ] !empty ] !empty` | list | !empty | REFUSED | own-key refusal text (refused true) (the refusal names `Rules`' own key `R1`; the disjunct itself is not refused) | eval_tests.rs:the_grounding_probe_is_a_quiet_reading_independent_of_what_ran_first (case "a_unary_filter_over_a_capture_grounds_nothing_through_its_predicate") |
   | `Resources.A.Properties.Rules[*][ R1 !exists or %t[ Value == 'prod' ] !empty ] !empty` | list | !empty | REFUSED | own-key refusal text (the refusal names `Rules`' own key `R1`; the disjunct itself is not refused) | eval_tests.rs:the_grounding_probe_is_a_quiet_reading_independent_of_what_ran_first (case "the_binary_filter_over_a_capture_control") |
   | `Resources.A.Properties.Rules[*][ R1 !exists or %t[ Value !exists ] empty ] !empty` | list | !empty | REFUSED | own-key refusal text (the refusal names `Rules`' own key `R1`; the disjunct itself is not refused) | eval_tests.rs:the_grounding_probe_is_a_quiet_reading_independent_of_what_ran_first (case "a_unary_absence_filter_over_a_capture_kept_empty_grounds_nothing") |
   | `Resources.A.Properties.Rules[*][ R1 !exists or %t[ Missing !exists ] !empty ] !empty` | list | !empty | REFUSED | own-key refusal text (the refusal names `Rules`' own key `R1`; the disjunct itself is not refused) | eval_tests.rs:the_grounding_probe_is_a_quiet_reading_independent_of_what_ran_first (case "a_unary_absence_of_a_key_the_capture_lacks_grounds_nothing") |
   | `Resources.A.Properties.Rules[*][ R1 !exists or %cfg[ keys == 'PROD' ] !empty ] !empty` | one-object | !empty | REFUSED | own-key refusal text (the refusal names `Rules`' own key `R1`; the disjunct itself is not refused) | eval_tests.rs:the_grounding_probe_is_a_quiet_reading_independent_of_what_ran_first (case "a_key_filter_over_a_literal_map_grounds_nothing") |
   | `Cfg[*][ Mode !exists Kind == 'k' this[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty ] !empty` | collection | !empty | PASS | none | eval_tests.rs:the_grounding_probe_is_a_quiet_reading_independent_of_what_ran_first (case "an_admitted_clause_failing_under_the_probe_is_neutral_beside_a_grounding_conjunct") |
   | `some Cfg[*][ Mode exists or M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty or Ref !exists ].Kind == 'k'` | collection | some + == | FAIL | none | eval_tests.rs:an_entry_held_without_grounding_does_not_decide_past_an_undecided_one (case "some after [*]: the undecided entry's marker alone answers") |
   | `some Cfg.%x.Kind == 'k'` and `some %sel.Kind == 'k'` under `let sel = Cfg[*][ x \| Mode exists or M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty or Ref !exists ]` | collection | capture binding; read by `some Cfg.%x.Kind == 'k'` and `some %sel.Kind == 'k'` | FAIL | own-key hint "meant as one object" on the marker `%x` holds | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one |
   | `Resources.*[ Properties.Cfg[*][ x \| R1 !exists ] !empty ]` | collection | !empty inside a predicate; sibling `some Resources.*.Properties.Cfg.%x.Kind == 'k'` | FAIL | own-key refusal text THE_REFUSAL on the marker at /Resources/R/Properties/Cfg | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "inside a predicate: the refused enumeration's capture holds the refusal's marker alone") |
   | `when Resources.*[ Properties.M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty ] !empty` | collection | when gate over !empty | FAIL | none | eval_tests.rs:the_hand_up_reading_of_an_undecidable_value_inside_a_unary_filter_is_pinned (case "a: a when gate under !empty fails its rule closed on the marker beside the kept entry") |
   | `let sel = Cfg[ y ][ Kind == 'k' ]` and `let sel = Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`, read by `%sel !empty` | n/a | n/a | `%y` reads keys ["Mode", "A", "B"] | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (cases "`Cfg[ y ][ Kind == 'k' ]`, no own key named", "`Cfg[ y ][ x \| Mode exists or Kind == 'k' ]`") |
   | `Cfg[ y ][ Kind == 'k' ]` | collection | wildcard capture then filter; `%sel !empty` | `%y` = [Mode, A, B] | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "`Cfg[ y ][ Kind == 'k' ]`, no own key named: `%y` is every key the wildcard enumerated") |
   | `.M[ keys == to_upper(Env) ]` | collection | continuation key filter; `some %sel == 1` | PASS | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "a later part of the same query reads the scope's root") |
   | `Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]` | collection | `this IN %x` continuation; `%sel !empty` | selection ["A", "B"] | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "the own-key spelling: `%x` is bound to each held key just before that entry is walked") |
   | `Cfg[ y ][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %y ]` | collection | `this IN %y`; `%sel !empty` | selection ["A", "B"] | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "the own-key spelling, the wildcard's own capture read mid-query") |
   | `let sel = Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]`, `let sel = Cfg[ y ][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %y ]` and their regular-spelling twins, read by `%sel !empty` | n/a | n/a | selection equals ["A", "B"] | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one |
   | `let sel = Cfg[*][ x \| Kind == 'k' ].Peers[ this IN %x ]` with `let n = count(%sel)` | collection (overlapping peers: `A.Peers: [A, B]`, `B.Peers: [B, Z]`) | `%n == 2`; `%n == 3` | `%n == 2` PASS; `%n == 3` FAIL | none | eval_tests.rs:a_peers_read_after_a_wildcard_filter_sees_the_keys_held_so_far |
   | `let sel = Cfg[*][ x \| Mode exists or Kind == 'k' ].Peers[ this IN %x ]` and `let sel = Cfg[*][ x \| Kind == 'k' ].Peers[ this IN %x ]`, read by `%sel !empty` | n/a | n/a | selection equals ["B", "A", "B"] over PEERS_REVERSED | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (cases "the own-key spelling over the entries in the other order", "the regular spelling over the entries in the other order") |
   | `.Tags[*][ Key == 'Env' ]` | mixed per entry | continuation; `.Value == 'prod'` under some, `.Value !empty` | PASS | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (cases "the rest of the query runs over the twin: `.Tags[*][ Key == 'Env' ]` over A's map-shaped `Tags` is decided by its pair (`dev`, failing `== 'prod'`), and `some` passes on B's list", "`!empty` twin: `.Value` read through the pair holds `dev` on A and `prod` on B, so the clause passes") |
   | `.Sub[*][ s \| R1 !exists ]` | collection | `!empty or Cfg.Fallback exists`; sibling `some Cfg.%x.Kind == 'k'` | FAIL | own-key refusal text THE_REFUSAL on the marker at /Cfg/A | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "an enumeration the continuation refuses") |
   | `Cfg[*][ x \| Kind == 'k' ].Sub[*][ s \| R1 !exists ]` | collection | `!empty or Cfg.Fallback exists`; sibling `some Cfg.%x.Kind == 'k'` | FAIL | own-key refusal text THE_REFUSAL at /Cfg/A | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "the regular spelling (`Cfg[*][ x \| Kind == 'k' ]`, no own key named)") |
   | `Cfg[ x \| Kind == 'k' ] !empty` | collection | !empty | PASS | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "a same-name capture another clause of the block filed before the refused walk") |
   | `.M[ keys == Names[*].Name ]` | collection | continuation !empty inside a predicate; sibling `some Resources.*.Properties.Props.%x.Kind == 'k'` | PASS | none | eval_tests.rs:a_capture_of_an_own_key_filter_holds_no_entry_held_without_grounding_beside_an_undecided_one (case "an undecidable the walk meets for another reason") |
   | `Statement[*][ Action !exists ] !empty` | one-object | !empty | REFUSED | own-key refusal text (refused true) | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "the all-intrinsic statement under a negated own key: kept by a miss, refused") |
   | `Resources[*][ BucketA exists ] empty` | collection | empty | PASS | none | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "a member named like the key alone under empty") |
   | `Resources[*][ "Fn::Transform" exists ]` | collection | empty and !empty | FAIL | own-key refusal text "a key of the map itself" | eval_tests.rs:a_directive_key_named_by_the_predicate_is_refused_and_the_walk_passes_a_directive_list_over (cases "[*], empty", "[*], not empty") |
   | `Resources[ f ]` | n/a | n/a | unpinned as a placeholder; the concrete spelling `Resources[ Properties.Tags !exists ].Type exists` is pinned PASS | none | none |
   | `Resources[*][ f ]` | n/a | n/a | unpinned as a placeholder; the concrete spelling `Resources[*][ Properties.Tags !exists ].Type exists` is pinned PASS | none | none |
   | `Resources.*[ f ]` | n/a | n/a | unpinned as a placeholder; the concrete spelling `Resources.*[ Properties.Tags !exists ].Type exists` is pinned PASS | none | none |
   | `Resources[ Properties.Tags !exists ].Type exists` | collection | key filter then `.Type exists` | PASS | none | eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling (case "key filter") |
   | `Resources[*][ BucketA !exists ].Type exists` | collection | `.Type exists` after an absence filter | PASS | none | eval_tests.rs:a_directive_beside_members_is_not_selected_under_the_absence_polarity |
   | `%r[ Properties.Tags empty ] !empty` | collection | !empty | FAIL | none | eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling (case "tagging idiom over a transform beside two tagged buckets") |
   | `Resources.*[ Name == 'AWS::Include' ].Parameters.Location == /^s3:\/\/approved-bucket\//` | directive beside a member | == regex | FAIL | none | eval_tests.rs:a_directive_is_handed_on_where_the_predicate_names_a_key_it_holds (case "unapproved include beside a bucket") |
   | `Tags[*][ Key !exists ] empty` | directive | empty | PASS | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "tags written as a loop under `Tags[*][ Key !exists ] empty`") |
   | `States[*][ Type !exists ] empty` | directive | empty | PASS | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "states written as a loop under the [*] spelling of `[ Type !exists ] empty`") |
   | `Resources.*[ Properties.Tags !exists ] empty` | directive | empty | PASS | none | eval_tests.rs:a_directive_is_handed_on_where_the_predicate_names_a_key_it_holds (cases "a loop alone", "an include alone") |
   | `Resources.*.Metadata[ Comment !exists ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "a resource's `Metadata` attribute holding only a transform") |
   | `Parameters[ Value !exists ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "a `Parameters` holding only a transform under `Parameters[ Value !exists ] empty`") |
   | `Parameters[ Type !exists ] empty` | directive | empty | PASS | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "a `Parameters` holding only a loop under `Parameters[ Type !exists ] empty`") |
   | `Resources.*.Properties.*[ Status !exists ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only |
   | `[ Tags !exists ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_directive_is_read_the_same_at_a_nested_map_and_beside_any_sibling (case "the include alone as `Properties` under `Properties.*[ Tags !exists ] empty`") |
   | `SecurityGroupIngress[*][ Description !exists ] empty` | a directive (a map holding a lone `Fn::Transform`) | empty | FAIL | member notice, directive sentence: "holds no member of its own, only the directive `Fn::Transform`", "hands ..." | eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance (case "a lone directive under `[*]`: the directive sentence") |
   | `Tags[*][ Value !exists ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "tags written as a transform under the [*] spelling of `[ Value !exists ] empty`") |
   | `Resources.*[ this IS_LIST ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling (case "a ForEach list beside two members, .*: `[ this IS_LIST ] empty` selects the list") |
   | `Tags.*[ Key !exists ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling (case "a one-key `Fn::If` tag list, .*: `Tags.*[ Key !exists ] empty`") |
   | `Target[*][ Name !exists ] empty` | directive | empty | FAIL | none | eval_tests.rs:a_directive_beside_members_is_passed_over_by_every_filter_spelling (case "a one-key `Fn::FindInMap` scalar list, [*]: `Target[*][ Name !exists ] empty`") |
   | `RegionMap[*][ "us-east-1" exists ]` | collection | empty | PASS | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only |
   | `%m[ ImageId !exists ]` | collection | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only |
   | `%m[ AMI !exists ]` | collection | n/a | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `Mappings.RegionMap.*[ AMI !exists ] empty` | collection | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "a transform beside the region entries of `Mappings.RegionMap`") |
   | `Parameters.*[ Default !exists ] !empty` | collection | !empty | PASS | none | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "a parameter named like the key, `Default !exists ] !empty`") |
   | `Parameters.*[ Default exists ] empty` | collection | empty | PASS | none | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "a parameter named like the key, `Default exists ] empty`: no parameter declares one") |
   | `Resources[*][ BucketA !exists ] !empty` | collection | !empty | PASS | member-move notice (1): "names `BucketA`, a key of the map at path /Resources", "Write ..." | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "bracket wildcard, a member named like the key negated: every resource is kept") |
   | `Resources.F.Properties.Tags[*]` | all-scalar | `[ Key == %w ] empty` | REFUSED | own-key refusal text "the predicate compares against `%w`, a name bound outside the predicate" | eval_tests.rs:a_capture_names_nothing_in_the_parameterized_rule_as_in_the_plain_one |
   | `Resources.*.Properties.Tags[*]` | all-scalar | `[ Type exists ] !empty` | FAIL | one-object notice: "names `Type`, a key of the value at path /Resources/Fn", "which `[*]` hands on as one ..." | eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance (case "an all-scalar map handed on as one object: the held move is announced naming the key") |
   | `%r[*]` | collection | `[ BucketA exists ] empty` in a type block | PASS | member-move notice (the bound map itself was the value probed) plus the bound-map notice | eval_tests.rs:the_member_notice_decides_on_what_the_predicate_kept_and_probes_each_site_once (case "control: a site whose probe read a hold (`%r[*]`: the bound map itself)") |
   | `Resources[*][ AWSTemplateFormatVersion exists ] !empty` | collection | !empty | FAIL | member-move notice HELD: "names `AWSTemplateFormatVersion`, a key of the document the map sits in and of no ..." | eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance (case "a key the document holds and no member holds (`AWSTemplateFormatVersion exists`)") |
   | `Resources.*.Properties.Tags[*][ Type exists ] !empty` | all-scalar | !empty | FAIL | the one-object held-move notice (names `Type`, a key of the value at the path) | eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance; eval_tests.rs:a_member_notice_over_a_block_on_a_literal_names_and_probes_the_literal |
   | `Resources[*][ BucketA exists Type == 'AWS::S3::Bucket' ] empty` | collection | empty | PASS | none | eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard (case "a member key conjoined with a key the map lacks under `empty`") |
   | `Resources[*][ Tags !exists ]` | collection | !empty | PASS | member-move notice, absence family: "where it held because no entry named `Tags` exists at that value" ... | eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance (case "the same hold under `!empty`: the verdict agrees") |
   | `Resources[*][ Tags !exists ].Type == 'AWS::S3::Bucket'` | collection | == continuation | PASS | member-move notice, absence family: "names `Tags`, a key the document the map sits in does not hold" | eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance (case "a hold by the absence of a key the document lacks (`Tags !exists`)") |
   | `Resources[*][ BucketA !exists M[ keys == Tags[ Key == 'Env' ].Value ] !empty ] empty` | collection | empty | FAIL | member-move notice "the selection moved from no member to an undecidable member" | eval_tests.rs:the_member_notice_names_the_selection_alone_and_keys_every_head_by_provenance (case "an undecidable member under `empty`: fails closed") |
   | `Resources.*.Metadata[*][ "AWS::CloudFormation::Init" exists ] empty` | collection | empty | PASS | none | eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard (case "the Init shape under `exists ] empty`: nothing selected") |
   | `resources[*][ limits exists ] empty` | collection | empty | PASS | none | eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard (case "a container's resources of limits beside requests under `exists ] empty`") |
   | `Resources.*.Metadata.*[ "AWS::CloudFormation::Init" exists ] empty` | collection | empty | PASS | none | eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard (case "the Init shape under `.*` and `exists ] empty`") |
   | `Resources.*.Metadata[*][ Type exists ] !empty` | collection | !empty | FAIL | member-move notice: "names `Type`, a key of the value at path /Resources/WebServer", "Write ..." | eval_tests.rs:the_member_notice_spells_its_advice_over_the_query_before_the_wildcard (case "the resource's own key `Type` asked of its Metadata members under `[*]` and `!empty`") |
   | `Resources.*.Metadata[*][ "AWS::CloudFormation::Authentication" exists ] empty` | one-object | empty | FAIL | own-key refusal text OWN_KEY_AUTHENTICATION, member spellings absent | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "sub_maps_sharing_no_key_name_are_one_object_and_the_own_key_is_refused_under_empty") |
   | `Properties[*][ BucketEncryption exists ]` | one-object | empty | REFUSED | own-key refusal text OWN_KEY_BUCKET_ENCRYPTION, member spellings absent | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "all_structure_properties_sharing_no_key_name_are_one_object_and_the_own_key_is_refused") |
   | `when %p[*][ BucketEncryption exists ] !empty` and `%p[*][ VersioningConfiguration exists ] empty` under `let p = Resources.*[ Type == 'AWS::S3::Bucket' ].Properties` | n/a | n/a | FAIL | none | eval_tests.rs:a_wildcard_filter_over_a_mixed_or_dot_enumerated_one_object_map_is_refused_by_name |
   | `%p[*][ BucketEncryption exists ] !empty` | one-object | when gate over !empty | REFUSED | none | eval_tests.rs:a_wildcard_filter_over_a_mixed_or_dot_enumerated_one_object_map_is_refused_by_name (case "the projecting binding over all-structure Properties, gate polarity") |
   | `Statement[*][ Action == '*' ] empty`, `Statement[*][ Action == '*' ] !empty`, `Statement[*] { Action == '*' }`, `Statement[*].Action == '*'` over the all-intrinsic one-object statement | all-intrinsic one-object statement | empty; !empty; block; == | `empty` FAIL; `!empty` FAIL; block PASS; `.Action == '*'` PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object |
   | `Parameters[*] { Default !exists }` | collection | block | REFUSED, FAIL as an assertion (`[*]` hands the map on whole; `Default` is a key of the map and the name of one member while `Other` holds no `Default` of its own, so the own entry would answer for every member) | the block-arm own-key refusal, one flagged record naming the map handed on whole at its path with its location (`/Parameters[L:0,C:0]`) and `Default`, the key the block reads; its remedy is written in the refusal's own grammar, `X.*.Key` for each member's own `Key`, "where `X` is `Parameters`" (the refusal never spells `Parameters.*.Default` out; the test reads the path, the key, `X.*.Key` and the binding of `X` on one message) | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (case "the block after the bracket wildcard is refused over the map's own key: the block arm's text, not the filter arm's opener") |
   | `Parameters[*].Default` | collection | key read | unpinned (no test asserts this cell) | none | none |
   | `Resources[*][ BucketA exists ]` | collection | !empty and empty | !empty FAIL / empty PASS over the members | none | eval_tests.rs:an_own_key_filter_after_a_wildcard_that_keeps_an_entry_is_not_refused (cases "`BucketA exists`, !empty: the selection keeps nothing", "a member named like the key alone under empty") |
   | `Statement[*] { Action == '*' }` | one-object | block | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "the_block_spelling_reads_the_all_intrinsic_one_object_statement") |
   | `Statement[*].Action == '*'` | one-object | == | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "the_key_spelling_reads_the_all_intrinsic_one_object_statement") |
   | `%r[*][ A exists ]` | collection | !empty | FAIL | none | eval_tests.rs:a_variable_query_root_enumerates_only_when_its_binding_did_not (case "filter_attribution_names_a_key_of_the_collection") |
   | `Resources[*] { BucketA exists }` | collection | block | REFUSED, FAIL as an assertion (`[*]` hands the map on whole; `BucketA` is a key of the map and the name of one member while another member holds no `BucketA` of its own, so the own entry would answer for every member, a false pass) | the block-arm own-key refusal, flagged, naming `BucketA` and the map handed on whole; its remedy is written in the refusal's own grammar, `X.Key == value` for the map as one object and `X.*.Key` or `X.* { Key == value }` for each member's own `Key`, "where `X` is `Resources`" (the refusal never spells `Resources.*.BucketA` out; the test reads the handed-on sentence, `X.*.Key` and the binding of `X`) | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "the_block_spelling_the_refusal_names_is_refused_over_the_maps_own_key") |
   | `Resources[*].BucketA exists` | collection | exists | REFUSED, FAIL as an assertion (the key read after `[*]` takes the block spelling's classification over a map handed on whole) | the same own-key refusal, flagged, in the same words (one text builder serves the block arm and the key arm): `X.Key == value`, `X.*.Key` or `X.* { Key == value }`, "where `X` is `Resources`" | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (case "the_key_spelling_the_refusal_names_is_refused_over_the_maps_own_key") |
   | `rule no_admin { %admin empty }` under `let admin = Resources.*[ Type == 'AWS::IAM::Policy' Properties.PolicyDocument.Statement[ Effect == 'Allow' Action == '*' ] !empty ]` | all-scalar | `%admin empty` | FAIL | named-map refusal text REFUSAL_HEAD "The filter selected nothing among the map's own entries. `Key` is ..." | eval_tests.rs:a_named_map_refusal_inside_a_filter_predicate_fails_the_whole_selection_closed |
   | `rule all_ok { %ok !empty }` under `let ok = Resources.*[ Type == 'AWS::IAM::Policy' Properties.PolicyDocument.Statement[ Effect == 'Deny' ] !empty ]` | all-scalar | `%ok !empty` | REFUSED | named-map refusal text | eval_tests.rs:a_named_map_refusal_inside_a_filter_predicate_fails_the_whole_selection_closed |
   | `Resources.*[ Type == 'AWS::IAM::Policy' Properties.PolicyDocument.Statement[*][ Effect == 'Allow' Action == '*' ] !empty ]` | all-scalar one-object statement | `%admin empty` | FAIL | own-key refusal text WILDCARD_HEAD on the all-intrinsic row only | eval_tests.rs:a_named_map_refusal_inside_a_filter_predicate_fails_the_whole_selection_closed |
   | `Statement[*] { Effect == 'Allow' Action == '*' }` | list | block | PASS | none | eval_tests.rs:a_named_map_refusal_inside_a_filter_predicate_fails_the_whole_selection_closed |
   | `Statement[*][ Effect == 'Allow' Action == '*' ] !empty` | top-level rule (the in-predicate spelling is the VIOLATORS_EMPTY_WILDCARD rows, FAIL for the whole rule) | !empty | PASS over the violating statement (`Allow` + `*`) and its list twins; FAIL over the compliant all-scalar statement and its list twin | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_tests_the_object (cases "one_object_violating_not_empty", "one_element_list_violating_not_empty", "one_object_compliant_not_empty", "one_element_list_compliant_not_empty") |
   | `Statement[ Condition !exists ]` | all-scalar | !empty | REFUSED | pass-over refusal text: "the filter `X[ Condition !exists ]` kept no entry and passed over `Effect`, a ..." | eval_tests.rs:a_named_map_refusal_inside_a_filter_predicate_fails_the_whole_selection_closed |
   | `Resources[ Properties.Tags !exists ] empty` | collection | empty | PASS | none | eval_tests.rs:a_directive_is_handed_on_where_the_predicate_names_a_key_it_holds |
   | `Templates[*].Resources` | collection | empty | PASS | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "a `Resources` holding only a loop, in a `Templates` list") |
   | `Properties.*[ Status !exists ] empty` | mixed | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only |
   | `Resources.*.Properties.*[ Name == 'AWS::Include' ] empty` | mixed | empty | FAIL | none | eval_tests.rs:a_lone_loop_is_passed_over_anywhere_and_a_lone_transform_at_a_section_only (case "an include beside `BucketName` under `Properties.*[ Name == 'AWS::Include' ] empty`") |
   | `Cfg[ Owner !exists this[ keys == to_upper(Env) ] !empty ] empty` | all-scalar | empty | REFUSED | own-key refusal text "`X` is `Cfg`. Write `X[*][ ... ]` to read one object and a list of them alike: the ..." | eval_tests.rs:the_one_object_probe_reads_the_fallback_and_carries_its_errors_as_the_bracket_reading_would (case "must-flag: over `Env: prod` the fallback read holds the key filter on `PROD`") |
   | `Cfg[ Owner !exists this[ Owner !exists ] !empty ] empty` | all-scalar | empty | FAIL | nested refusal text "`X` is the member the block is over." | eval_tests.rs:the_one_object_probe_reads_the_fallback_and_carries_its_errors_as_the_bracket_reading_would (case "must-flag: a refusal raised inside the predicate is carried out of the probe") |
   | `spec.*[ securityContext !exists ] !empty` | mixed | !empty | PASS | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling (case "dot wildcard over the spec with replicas beside the sub-maps") |
   | `spec[ securityContext !exists ]` | mixed | !empty | REFUSED | none | eval_tests.rs:a_scalar_entry_is_passed_over_by_a_filter_over_the_maps_entries_under_every_spelling (case "literal gate over the same spec: refused, fail closed") |

   > **Workaround**: write the clause as a block over the wildcard or as the wildcard then the key,
   > `Statement[*] { Action == '*' }` or `Statement[*].Action == '*'`, which read the one-object statement
   > and the list the same way in both polarities. `Resources[*][ BucketA exists ]` and `%r[*][ A exists ]`
   > over `let r = Resources` are refused the same way over a map that is not a collection of members
   > (an intrinsic call under a key that is not an `Fn::` directive beside the members, or sub-maps that
   > share no key name), and are the selection the
   > author wrote over a map of plain members sharing a key name (above); a stray scalar beside the
   > members (`Note: 'a string'`) makes the map one object under `[*]`, so `BucketA exists` holds on the
   > map itself and `empty` fails where `!empty` passes, with no refusal;
   > `Resources[*] { BucketA exists }` or `Resources[*].BucketA exists` read the map's own key either way.

   **Inside a filter predicate.** The same refusal after a key, met inside another filter's predicate, is not
   the entry's marker but the whole outer filter's. Under the set-of-violators spelling
   `let admin = Resources.*[ Type == 'AWS::IAM::Policy' Properties.PolicyDocument.Statement[ Effect == 'Allow'
   Action == '*' ] !empty ]` with `rule no_admin { %admin empty }`, a policy whose `Statement` is written as one
   object (`Statement: { Effect: Allow, Action: '*' }`) refuses the outer filter whole, held at the clause that
   reads the binding, so the rule fails at exit 19 and the policy is never silently dropped from the set; the
   compliant-set spelling, `let ok = Resources.*[ Type == 'AWS::IAM::Policy'
   Properties.PolicyDocument.Statement[ Effect == 'Deny' ] !empty ]` with `rule all_ok { %ok !empty }`, fails
   the same way, so the policy is never picked up as compliant either (exit 19 in both, measured by the test suite
   of this tree). The cost is wider than the violator: a COMPLIANT one-object policy (`Statement: { Effect: Allow,
   Action: 's3:GetObject' }`) is refused by the same reading and fails `no_admin` where its list twin passes, and
   the siblings written after the refused policy in the template are not decided at all (the loop runs in the
   order the resources are written, not in key order, and stops at the refusal; a sibling written before it was
   already decided and is recorded, even when its key sorts after the refused one). This differs from
   `Statement.*[ ... ]` inside a predicate, which is refused per entry as an undecidable marker with the siblings
   still decided (the behavior-change callout on a wildcard filter refused inside a filter predicate in
   [Guard: Clauses](CLAUSES.md)). The form that decides is `[*]` before the filter inside the predicate,
   `Resources.*[ Type == 'AWS::IAM::Policy' Properties.PolicyDocument.Statement[*][ Effect == 'Allow' Action ==
   '*' ] !empty ]`: `Statement[*]` hands a one-object statement to the filter as its one member and enumerates a
   list, so every policy whose statement holds a literal scalar entry is decided with no refusal; a statement
   written entirely with intrinsics (`!Ref`, `!If`) has no scalar entry, is read as a collection, and the `[*]`
   filter is refused over it as item 15 above says, the policy answered with an undecidable marker. The Workaround
   above does not fit this case for a different reason: `Statement[*] { Effect == 'Allow' Action == '*' }` and
   `Statement[*].Action == '*'` ask whether EVERY statement matches (the dotted form also loses the pairing of
   `Effect` with `Action`), so a policy with one admin statement beside one benign statement is left out of
   `%admin` and `no_admin` passes, a silent false negative; a set of violators needs SOME statement matching both,
   which only `Statement[*][ Effect == 'Allow' Action == '*' ] !empty` expresses. The other refusal a filter after
   a key can raise, the pass-over of scalar entries (`Statement[ Condition !exists ]` over a statement written
   as one object of strings: the filter kept nothing and passed over `Effect`, a string), behaves the same way
   inside another filter's predicate: the refusal is the outer filter's, the siblings are not decided, where
   `[*]` and `.*` refusals mark one entry instead; the per-entry marker `[*]` and `.*` refusals use is the
   alternative on record.

   The block and key spellings after `[*]` read the same map differently from the filter spelling. Over a
   candidate collection (two or more plain member maps sharing a key name, no scalar or intrinsic entry) whose
   OWN key names a member, whether or not every member carries it, `X[*] { Key .. }` and `X[*].Key` are refused per
   value, in every role, with the remedy naming the direct path (`X.Key`) and the member spellings
   (`X.*.Key`, `X.* { Key .. }`), where the released evaluator answered them from the map's own entry
   (`Resources[*] { Type exists }` passing over `Resources: { Type: { Name: x }, B: { Type: .., Name: y } }`
   though the member `Type` has no `Type` of its own); the key read after a binding of the wildcard (`let r = Resources[*]` then
   `%r.A.S`, `check(Resources[*])` then `%p.A.S`) is the same read and gets the same refusal, the remedy's `X`
   the source query before its `[*]`, never the bare `%r`. The filter spelling, `X[*][ Key == value ]`, keeps
   the one-object reading this item describes and its notice. So a rule that spells one check three ways
   can read one map three ways: refused by the block and key spellings, decided or refused by the filter
   spelling as this item says. The clause table (`docs/CLAUSES.md`, the own-key rows) states each spelling's
   reading; whether an ordinary configuration map should draw a notice rather than a refusal from the block
   and key spellings is an open design question.

16. <a name="regex-against-the-keys-of-a-one-object-map"></a> A filter straight after `[*]` over a map read as one object is refused when the predicate compares against keys of
   which the object holds none, the filter kept nothing, and the selection is then read after the filter other than as
   the shape the rule was written for: by a key the object also lacks, by a held key beside an entry the predicate
   compared against or with nothing beside it, or bare (`exists`, `empty`, their negations, a `when` gate) while the
   object holds an entry the predicate compared against; in the filter's own query or from the selection it left (the
   block form's body, a binding read later, a parameterized rule's parameter), since 3.2:
   `Properties.Tags[*][ Key == 'Env' ].Value == 'prod'` over map-shaped tags, `Tags: { Env: dev }`, exits 19 (today on
   the compared value `dev`, through the list twin described at the end of this entry; before the twin, with the
   refusal naming `Key`), where it was not applicable at exit 0 (so in the released 3.1.12, 3.2.0 and 3.2.1 binaries too, measured: not applicable at exit 0, the predicate asked of the resource that holds the tags, which has no `Key`; and so over list-shaped tags in those releases, which fail at exit 19 now on the compared value). The general rule is the part after the filter: that is
   where a value that is not there gets compared; when that part reads a key the object holds, `Statement[*][ Principal ==
   '*' ].Effect == 'Deny'` over a managed policy's one-object statement with no `Principal` (every statement holds
   `Effect`), the object is the shape the rule was written for and only lacks an optional key, so the clause is the
   empty selection its list twin is, not applicable at exit 0, where `[ Action == '*' ].Condition exists` over a
   `NotAction` statement with no `Condition` reads a key the object also lacks and is refused. A second filter after the
   first is read as that key is: `Statement[*][ Principal == '*' ][ Effect == 'Allow' ] empty` names `Effect`, a key the
   object holds, and passes as its list twin does, where `[ Principal == '*' ][ Sid == 'x' ]` names only a key the object
   also lacks and is refused; a wildcard or an index after the filter is refused. Inside a filter predicate
   the same two conditions decide: `Resources.*[ Properties.PolicyDocument.Statement[*][ Principal.AWS == '*' ].Effect
   == 'Allow' ] empty` deselects a managed policy whose one-object statement has no `Principal` (`Effect` is held) and
   passes, selects a bucket policy whose `{ AWS: '*' }` principal allows and fails it, as the chained `[ Principal.AWS ==
   '*' ][ Effect == 'Allow' ] !empty` does, where `[ Action == '*' ].Condition
   exists` inside the predicate over a `NotAction` statement with no `Condition` is still the undecidable marker and
   fails closed. The marker is per entry: the other policies under `Resources.*` are still read and decided, so the
   record names the refused policy beside the verdicts of the rest rather than stopping at it. With nothing after the
   filter the selection is decided by what the object holds, for an object the twin does not read (a map with a
   non-scalar entry beside the compared one, `Tags: { Env: dev, ENV: !Ref Stage }`, or a predicate outside the pair
   convention; over a map of scalars, `Tags: { Env: dev }`, every pair-shaped predicate is decided by the map's `{ Key,
   Value }` list twin, the end of this entry, and nothing in this paragraph is refused): over such an object holding an
   entry the predicate compares a key against, under any operator and in any clause (that map under `[ Key == 'Env' ]`,
   `[ Key IN ['Env', 'Environment'] ]`, `[ Key != 'Env' ]`, `[ Key == 'Owner' or Key == 'Env' ]` or `[ Key == 'Env' Value
   == 'prod' ]`, and under `[ Key == /^Env$/ ]` or `[ Key == /Env/ ]`), the map is not read as its list twin would be, so
   `Tags[*][ Key == 'Env' ] exists`, `!exists`,
   `empty` and `!empty` are refused in both polarities, over the inline filter, the bare binding and a parameter alike
   (every unary operator decides the bare read so, the type checks `is_string`, `is_list`, `is_struct`, `is_bool`,
   `is_int` and `is_float` included),
   and `when %env !empty { ... }` or `when %env exists { ... }` fails its rule closed at exit 19 instead of leaving the
   block unopened (the refusal names the entry held and the key compared against it and claims nothing about what the
   twin would select: under `!=` or a second conjunct the twin can be empty and the map is refused all the same, so `[
   Key == 'Env' Value == 'prod' ] empty` over that map is refused where its list twin passes, and so is `[ Key ==
   'Owner'  Value == 'Team' ] empty` over `{ Team: x, ENV: !Ref Stage }`, whose only match is the value-side literal `Team`:
   the compared-entry test reads every clause's values against the entry's name whatever key the clause compares, and
   fails closed on that coincidence); over such an object
   holding no such entry, `{ Team: platform, ENV: !Ref Stage }`, under a SELECTING comparison (`[ Key == 'Env' ]`, `IN`)
   the four are decided as the one-element list decides them, not applicable, not applicable, pass and fail at exit 0
   under a gate (the twin's four answers over the all-scalar `{ Team: platform }` too), where under a NEGATED comparison
   (`[ Key != 'Env' ]`, `[ Key NOT IN ['Env', 'Environment'] ]`, a negated regex) the twin would select every pair the
   negation does not exclude, so such an object holding an entry that no negated clause excludes is refused (over the
   all-scalar map the twin keeps the pair and `empty` fails, as over the list; the refusal names `Team`, the entry the
   negation does not exclude, and the key that clause
   compares; `[ Key != 'Env' ] empty` over `{ Team: platform }` is refused where the twin
   fails, and `when %others !empty { ... }` fails its rule closed where the twin opens the block). The negation test reads
   each negated clause against the field of the twin pair `{ Key: <name>, Value: <value> }` its key names: a clause on
   `Key` excludes the entry by its name, a clause on `Value` by its scalar value, and a clause on any other key compares
   a field the pair has not, so it selects nothing, the predicate's `and`/`or` structure kept (one true disjunct selects the
   pair whatever the others read: `[ Key != 'Env' or Value != 'prod' ] empty` and `[ Value == 'prod'  Key != 'Env' ] empty` over
   `{ Team: prod }` and `[ Key != 'Env' or Action != '*' ] empty` over `{ Team: platform }` are refused as their twins are
   selected); the selecting test beside it stays shape-agnostic and holds every
   compared value against the entry's name whatever key the clause compares, because a selection fires on a coincidence
   and a negation on the absence of one. The pair the negation test reads is the tag convention's `{ Key, Value }` and
   no other: a one-object map written under another list convention, an environment-variable map keyed by the
   variable's name under `Env[*][ Name != 'x' ] empty` or `[ Values != 'x' ] empty`, is read as a statement under
   `[ Action != '*' ]` is, the negation selecting nothing, and keeps the empty selection where the `{ Name, Values }`
   list such a rule is written for fails on its entry; the engine cannot tell that convention from a statement field
   whose list form agrees, so this is a documented limit, not a refusal. So an entry some negated clause does exclude
   (`{ Team: platform }` under `[
   Value != 'platform' ]`, whose twin pair carries `platform`), an object under a negated clause on another key
   (`Statement[*][ Action != '*' ] empty` over a one-object `NotAction` statement) and an object a selecting conjunct
   names no entry of (`{ Team: platform }` under `[ Key == 'Env'  Value != 'prod' ]`, whose twin fails `Key == 'Env'`)
   keep the empty selection and pass `empty` as the twin does, `{ Team:
   Env }` under `[ Key != 'Env' ] empty` is refused as its twin `{ Key: Team, Value: Env }` is selected, and a one-object
   statement that lacks the key the
   predicate compares passes `empty` as its list twin does (`Statement[*][ Principal == '*' ] empty` over an
   identity-policy statement, `[ Action == '*' ] empty` over a `NotAction` statement, `[ Resource == '*' ] empty` over a
   trust-policy statement, `[ Principal.AWS == '*' ] empty` over a statement with no `Principal`). The bare read is
   delivered as the key reads are, the held refusal outside a filter predicate and the undecidable marker for the
   object inside one, so `some` cannot decide past it with a sibling. Inside a filter predicate the refusal is the
   undecidable marker for the map under test, so `Resources.*[ Properties.Tags[*][ Key == 'Env' ].Value != 'prod' ]
   empty` fails the dev-tagged function rather than deselecting it. Eight limits stand, each over a map the twin does not
   read, `{ Env: !Ref P, Team: platform }` (a non-scalar entry beside the compared one); over map-shaped tags of scalars
   every pair-shaped predicate is the twin's, as the end of this entry says, and the twin's answer is given beside each:
   a predicate that only asks whether its keys exist or are empty is not refused, so `Tags[*][ Key exists ] !empty` over
   that map is the empty selection (over `{ Env: dev }` the twin keeps the pair and it passes, as over the list);
   map-shaped tags whose every value is an intrinsic, `Tags: { Env: !Ref Stage }`, have no scalar entry,
   so they are a collection by their shape and `Tags[*][ Key == 'Env' ].Value == 'prod'` enumerates them and is not
   applicable at exit 0, the same all-intrinsic limit the one-object statement has (entry 15); a predicate that compares
   against a `%variable` bound to a query or a function call, or against a query or a call written in place, names no
   entry the refusal can read, so over that map `let wanted = Parameters.Wanted.Default` then `let env =
   Resources.*.Properties.Tags[*][ Key == %wanted ]` with `when %env !empty { %env.Value == 'prod' }` leaves the block
   unopened at exit 0 even when the parameter's default is `Env` (resolving a query-bound name is the quiet reading's
   work, never this read's, so the answer is the same whether or not an earlier clause resolved it), while over `{ Env:
   dev }` the same rule is refused at exit 19 with the twin's sentence (a name whose value is not fixed at the filter
   cannot be read as a pair), and a `%variable` bound to a LITERAL, `let wanted = 'Env'`, is the literal to the twin, so
   the rule fails on `dev` as `[ Key == 'Env' ]` does; a filter capture (`Mappings.TagPolicy.Wanted.Keys[*][ w | this ==
   'Env' ] exists`, then `[ Key == %w ] !empty`), the rule's own or a file-level `let`'s, is read as the query-bound name
   it is declared by and names nothing, so over that map the gate stays shut and over `{ Env: dev }` the read is refused
   at exit 19, in either rule order (a capture declared by a file-level `let` is bound only when that `let` is first
   read; a name an inner block merged up hides the enclosing binding of the same name for the same reason, in every
   clause of the block that receives it: a block's literal `let t = 'x'` is not read over the key an inner block handed
   up under `t`, so `%t IN ['Nope']` compares the captured key the shadowing notice names, and the notice asks the author
   to rename one of the two);
   a parameter of a called rule is read as its argument is, so with
   `rule chk(w) when Resources.*.Properties.Tags[*][ Key == %w ] !empty { ... }` the call `chk('Env')` is the literal
   spelling (over `{ Env: dev }` the twin decides it and the body runs; over that map it names `Env` and is refused),
   `chk(%wanted)` reads what the caller holds for `wanted` (the literal `let` is the literal, the query-bound one
   nothing), and `chk(Parameters.Wanted.Default)` names nothing, so over that map the gate stays shut and the call is not
   applicable at exit 0, and over `{ Env: dev }` it is refused at exit 19, the one answer the `let` spelling of that
   binding gives (the parameterized scope and the `let` spelling answer alike: a query-bound parameter names nothing in
   both). A `.Value` read straight after the filter, `rule chk(w) { ...[ Key == %w ].Value == 'prod' }`, is refused
   under a query-bound parameter over both maps (the lacks-keys refusal above over that map, the object having no `Key`
   and no `Value`; the twin's refusal over `{ Env: dev }`, the name's value not fixed at the filter), and under a
   literal argument is the twin's over `{ Env: dev }` (fails on `dev`) and refused over that map, so the gate is the
   shape that asks about the parameter. A name the called rule's own `when` captured is read before a same-named
   capture of the caller's, the order the rule's own reads take; a filter capture binds the kept pairs over `{ Env: dev
   }`, so `let env = Resources.*.Properties.Tags[*][ t | Key == 'Env' ]` then `%t.Value == 'prod'` fails on `dev` as
   `%env.Value == 'prod'` does, and a bare `exists` in the capturing clause itself, `Tags[*][ t | Key == 'Env' ] exists`,
   passes as the plain spelling does, while over that map the capture carries no refusal to the name it binds, so
   `%t.Value == 'prod'` is the empty selection at exit 0 where `%env.Value == 'prod'` is refused (and the bare `exists`
   is refused as the plain spelling is); a function call over the selection, `let n =
   count(Resources.*.Properties.Tags[*][ Key == 'Env' ])` then `%n == 0`, is decided at the call's argument as the bare
   `exists` is: over `{ Env: dev }` it counts the pair the twin kept (1, as the list counts); over a map the twin cannot
   read that HOLDS the compared entry (`{ Env: { Ref: p }, Team: platform }`) the call is refused, where the one-element
   list counts 1, and over such a map that holds no compared entry (`{ Team: platform, Other: { Ref: p } }`) it counts 0
   and `%n == 0` passes, the list twin's answer; a block body that hands the selection
   to a parameterized rule, `Tags[*][ Key == 'Env' ] { check(this) }` with `rule check(p) { %p.Value == 'prod' }`, hands
   the parameter the kept pair over `{ Env: dev }` (`%p.Value` is `dev`, the rule fails) and, over that map, the
   selection with its note, so `%p.Value` is refused (and a key-rooted read in the
   called rule's own body, `rule check(p) { Value == 'prod' }`, reads the selection too, never the object's entries) as
   `{ check(Value) }`, `{ this[*] { Value == 'prod' } }` and `{ this.* { Value == 'prod' } }` (a wildcard over the one
   object, refused as `.*` after the filter is), `{ Value == 'prod' }`, `{ let v = Value  %v == 'prod' }`, `{ let v =
   this.Value  %v == 'prod' }`, `{ when is_prod_stack { Value == 'prod' } }` while the condition holds (the gated body
   reads nothing while it does not, so the block is not applicable, as the rule-level `when` is), `{ this { Value ==
   'prod' } }` and a nested block over an alias of `this` (`{ let v = this  %v { Value == 'prod' } }`, `rule check(p) {
   %p { Value == 'prod' } }` called as `check(this)`, each one refusal) are refused, each clause of a body judged on the
   key it reads, so `Statement[*][ Principal == '*' ] { Effect == 'Allow'  Condition exists }` over a one-object
   statement without `Condition` is refused on `Condition` where `{ Effect == 'Allow' }` alone is not applicable, and
   the keys a body read are judged together afterwards as the inline chained filter judges its predicate's keys, so a
   body that read every key the object has (`{ Effect == 'Deny' or Action != '*' or Resource != '*' }` over a statement
   of nothing but those three, whether it reads them directly, through an alias of `this` such as `let v = this` read
   as `%v.Effect` or a parameter bound to `this`, or partly through a second filter in the body such as `this[ Effect
   == 'Allow' ] empty`) answers as `Statement[*][ Principal == '*' ][ Effect == 'Allow' Action == '*' Resource ==
   '*' ]` does, refused under this entry's every-key reading, while a body that read some of them beside others is the
   empty selection (the body runs as a QUIET DISCOVERY of the reads it makes, since the list twin never runs that body:
   nothing the body does along the way is recorded, no capture it binds reaches the clauses after the block, no rule it
   calls is memoized, and only the refusal is recorded, by the block itself; a data-dependent error the body meets
   there, a value it cannot read as the clause asks, is treated as a refused read, so the block fails closed and the run
   goes on, while an error in the body's own text, `{ %nosuch == true }` with no such variable or a call to a rule the
   file does not declare, stops the run as it does everywhere else, the same whichever shape the data has; the body is
   judged clause by clause wherever a clause of it is evaluated, so a
   body that read no key and one of whose clauses decides on nothing read from the selection is refused as `{ %flag ==
   true }` is, a bare read beside that clause (`{ this exists  %flag == true }` in either order, `{ let v = this  %v
   exists  %flag == true }`) excusing nothing but itself, one level down as well (`{ when %gate == true { this exists
   %flag == true } }`, `{ check(this) }` with `rule check(p) { %p exists  %flag == true }`, and `{ %flag == true  this {
   this exists } }` in either order, whose refusal names the body that holds the deciding clause, never the nested `{
   this exists }` alone), where a bare read handed to a binary comparison or a function argument (`{ let v = this  %v ==
   'x' }`, `{ this == %x }`, `{ let n = count(this)  %n == 0 }`) is a read of the selection, decided as the unary read
   is: over an object holding no entry the predicate compared against it is kept, the comparison or the function
   decides over nothing and the clause reading the result is not refused (nor is a later clause reading the memoized
   result, `{ let n = count(this)  %n == 0  %n < 10 }`, or a value derived from it, `{ let l = to_lower(this)  let m =
   %l[*]  %m == 'x' }`); over an object that holds such an entry (`{ Env: { Ref: p }, Team: platform }` under `[ Key
   == 'Env' ]`) the read is refused there, as `{ this exists }` is, and a body that read a held key beside the object's other keys (`{ Effect exists  %flag == true }` over a
   statement of `Effect`, `Action` and `Resource`) is judged on that key alone, as the chained filter `[ Effect exists
   %flag == true ]` is, and is the empty selection; a body one of whose reads was refused is refused by that read alone, the FIRST one
   refused, even when the refused clause sits in a disjunction another disjunct decides (`{ Sid == 'x' or %flag == true }` over a
   statement without `Sid` is refused naming `Sid`, as the chained `[ Sid == 'x' or %flag == true ]` is, not a second time naming the
   body) and when a gate-role body runs on to a second refused read (`{ Sid == 'x'  Condition exists }` names `Sid`); and once the
   selection has refused a read, the refusal's own sentence is the one the block records, whichever
   data-dependent error another clause of the body raised before or after it;
   and outside a filter predicate the refusal is held at the clause whatever the quantifier, so `some
   Resources.*.Properties.Tags[*][ Key == 'Env' ] { Value == 'prod' }` over one map-shaped and one list-shaped function
   fails as the inline `some` spelling does, the list's passing value deciding nothing past it); a one-object statement
   that lacks
   two optional keys, `Statement[*][ Principal == '*' ].Condition exists` over a statement with neither `Principal` nor
   `Condition`, reads a key the object also lacks and is refused at exit 19 where the one-element list is not applicable
   at exit 0, so a rule that asks every public statement for a condition is written with a guard, `Statement[*] { when
   Principal == '*' { Condition exists } }`, which is not applicable over a statement with no `Principal`, fails one
   whose principal is `*` and has no `Condition`, and passes one that has it, as one object and as a list alike; and a
   name regex that matches every string, lookaheads and negated classes included (`[ Key == /^(?!aws:)/ ]`, the usual
   "skip the reserved `aws:` tags", or `/[^:]/`), matches every key of the object and every probe string too, so it is
   read as about the value and names no entry, so a key read through it over a one-object statement (`Statement[*][ Sid
   == /^(?!aws:)/ ].Effect == 'Deny'`) is the empty selection its one-element twin is, not a refusal: no string probe
   tells such a regex from `/.+/`; write the literal key or `[*]`. Over a tag map that silence is now the twin's: a PAIR-SHAPED predicate (every
   clause on `Key` or `Value`, `[ Key == /^(?!aws:)/ ]` included) over a map of scalar entries is decided by the map's `{ Key,
   Value }` list twin, as item 15 above says, so `Tags[*][ Key == /^[A-Za-z]+[0-9]$/ ] empty` over `{ Env1: dev }`,
   `/^[A-Z][a-z]+$/` or the Sid alphabet `/^[A-Za-z0-9]+$/` over `{ Env: dev }`, the alphabet over the two-tag `{ Env1: dev,
   Team: a }` and `/^(?!aws:)/` over any tag map fail at exit 19 on the selected pair as the list form does, under every
   polarity (`!empty`, `exists`, `!exists`, a type check such as `is_struct` inside a predicate, the `when %env !empty { ... }`
   gate), and a regex matching no key of the map keeps the empty selection on both sides. What stays refused, fail closed, is
   a predicate the twin does not decide, one whose clauses name a field outside the pair convention: a filter whose clauses
   name fields outside the tag-pair convention is not read as a tag list; its empty selection is refused as undecidable.
   There one polarity of the silence is closed: under a bare `empty`, or a `when %s empty { ... }` gate over a binding to
   the filter, a selecting regex (`==`, `IN`; not a negated one) that matches EVERY key the object holds is refused at exit
   19 instead of passing by holding nothing, the refusal naming the regex, the key its own clause compares (`Sid` for `[
   Principal == '*' or Sid == /^\w+$/ ]`, where the refusal opens on `Principal`, the predicate's key the object lacks) and
   the key it matched: `[ Sid == /^\w+$/ ] empty` over a one-object statement without `Sid`, `[ NotResource == /.+/ ] empty`
   over a statement without `NotResource`, each where the statement's one-element twin (no such key in it) is the empty
   selection and passes. The other polarities over the same selection stay as the object decides them outside a filter
   predicate: `!empty` fails, the safe side, and `exists`, `!exists` and the type checks are not applicable, so `[ Sid ==
   /^\w+$/ ] !exists` over that statement is `SKIP` at exit 0 (the limit). Inside a filter predicate those answers are not
   the safe side, since a clause that does not hold deselects the entry under test, so there every unary operator whose
   answer over the empty selection would deselect the entry that a selection of every matched key would keep is refused
   too, by one rule over the operator's semantics and not by a listed set: `!empty` (fails over nothing), `exists`,
   `is_struct`, `!is_string`, `!is_list`, `!is_bool`, `!is_int`, `!is_float` and `!is_null` (not applicable over nothing,
   where a kept entry is a struct) and the inner bare `empty` (passes over nothing where a kept entry fails), so
   `Resources.*[ Properties.PolicyDocument.Statement[*][ Sid == /^\w+$/ ] is_struct ] empty` over a one-object statement
   without `Sid` is refused where the one-element list is not applicable on the inner check and passes (the refusal names
   the operator and the predicate context, and the enclosing clause fails closed on that entry while the others are
   decided); `!exists`, `!is_struct`, `is_list`, `is_string`, `is_bool`, `is_int`, `is_float` and `is_null` are not, since the
   map's not applicable and a kept entry's fail both deselect. The same negated name regex reads differently by the object's key count: over
   the one-key `{ Env: dev }` it matches every key and the probes and names nothing, while over the two-key `{ Team: a,
   Env: dev }` `/^[^T]/` matches `Env` and not `Team`, names `Env`, and refuses; so a rule written with a negated name
   regex is refused over some maps and silent over others, which is the limit, not a reading to rely on. The
   held key is not read by its name alone: the object must also hold no entry the predicate compares a key against,
   under any operator and any of its clauses (a string literal, each element of a list under `IN`, a regex, a `!=` or
   `NOT IN`, every `or` alternative), and must hold another key beside the key read. The shapes this reading reaches
   are the ones the twin cannot read (the closing paragraph of this entry): a map holding a non-scalar entry, and a
   predicate naming a field outside the pair convention. So map-shaped tags with a tag literally named `Value` whose
   value is a map, `Tags: { Env: dev, Value: { Ref: X } }`, which hold `Env`, are refused under `Key == 'Env'`, `Key IN
   ['Env']`, `Key IN ['Env', 'Environment']`, `Key == /Env/`, `Key != 'Env'` and `Key == 'Owner' or Key == 'Env'`
   alike, where tags with no `Env` beside such a tag, `{ Team: a, Value: { Ref: X } }` or `{ Value: { Ref: X } }`, are
   the empty selection their list twin is (over `Tags: { Env: dev, Value: x }`, every entry a scalar, the twin decides
   the same predicates and nothing is refused). The refusal's advice names the entry a selecting clause compares
   against when the object holds it, read over every clause (`Environment` for `Key IN ['Env', 'Environment']` over `{
   Environment: dev, Value: { Ref: X } }`, so "`X.Environment` reads it"); under a negation, `Key != 'Env'` or `Key NOT
   IN 'Env'`, it names no entry, since that is the one the author excluded. A regex compared against a key is matched
   against the object's key names for that test, and when it matches EVERY key of such an object its own STRUCTURE
   says what it names. One about the value, a body that is nothing but wildcards and character classes that stand
   for a set, with their quantifiers (`/.+/`, `/./`, `/^\w+$/`, `/^[A-Z]/`, the IAM Sid alphabet `/^[A-Za-z0-9]+$/`,
   the letters-only `/^[A-Za-z]+$/`, a negated class `/^[^T]/`, a listed class under a quantifier `/[Ee]+/`, a POSIX
   class `/^[[:alpha:]]+$/`, a Unicode class `/^\p{L}+$/`, and `/\A.+\z/`, whose `\A` and `\z` are the anchors `^` and
   `$` are: the body is read from the parsed pattern, not from its characters), names no entry, since it says nothing
   about which entry was meant: that keeps `Statement[*][ Sid == /.+/ ].Effect == 'Deny'` and `Statement[*][ Sid ==
   /^[A-Za-z0-9]+$/ ].Effect == 'Deny'` over a one-object statement the empty selection its list twin is, and
   `Statement[*][ Sid == /^[A-Za-z]+$/ ] exists`, `[ Sid == /^[[:alpha:]]+$/ ] exists` and `[ Sid == /^\p{L}+$/ ]
   exists` over a statement holding only `Effect`, as `Tags[*][ Key == /^[A-Za-z]+$/ ] exists` and `[ Key ==
   /^[[:alpha:]]+$/ ] exists` over `Tags: { Env: dev, ENV: { Ref: Stage } }` (both keys matched, `ENV` not a scalar),
   not applicable with no refusal; the bare `empty` over any of them is refused by the every-key sentence above
   (`Statement[*][ Sid == /^\w+$/ ] empty` over that statement, `[ Key == /^[A-Za-z]+$/ ] empty` over that map), fail
   closed. One written for a name, a body that begins or ends with a literal (`/^Env$/`, `/Env/`, `/^E/`, `/^Z/`, the
   mixed `/^E\w+$/`, the tag prefix `/^aws:/`; an unquantified class of LISTED characters, which spells one position of
   a name, `[Ee]` for `E` or `e`, so `/^[Ee][Nn][Vv]$/` and `/^[Ee][Ff][Ff][Ee][Cc][Tt]$/` are name regexes as `/^Env$/`
   is; `/^x*.+$/`, `/^\w+s?$/` and `/^E?/`, whose literal under a quantifier is still a literal), names the entry it
   matches whatever the object's key count: `Tags[*][ Key == /^[Ee][Nn][Vv]$/ ] exists` over `{ Env: dev, ENV: { Ref:
   Stage } }` is refused naming `Env`, and `Statement[*][ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists` and `[ Sid ==
   /^\w+s?$/ ] exists` over `{ Effect: Allow }` are refused naming `Effect`, in both polarities, as `[ Key == 'Env' ]`
   over the mixed map is. A regex whose structure says neither (a group, an alternation, a lookaround, a flag group
   such as `/(?i)^env$/`, a literal only in the middle, a pattern the syntax does not parse) is read by three probe
   strings unlikely as key names (the NUL character, and the identifier-like `zZ9` and `Zz9`; a probe that is itself a
   key is skipped): it is about the value when it matches one of them (`/^(?!aws:)/`, so `[ Key == /^(?!aws:)/ ]
   exists` over the mixed map is not applicable), written for a name otherwise (`/(?i)^env$/` matches none of them
   and is refused naming `Env` over the mixed map). Over a map of scalar entries
   none of this is reached: `/^Env$/`, `/^Z/`, `/(?i)^env$/`, `/^[Ee][Nn][Vv]$/` and the letters-only class over `Tags:
   { Env: dev }` or `{ Zone: a }` are all decided by the twin, which selects the pair, so `[ Key == /^[A-Za-z]+$/ ]
   !empty` opens its gate and fails on `dev`. A
   name regex that matches SOME keys of the object names the first of them in the object's order, structure and probes
   alike unasked: `[ Sid
   == /^E/ ].Effect == 'Deny'` over `{ Effect: Allow, Env: dev, Action: '*' }` is refused naming `Effect`. The
   block form `Tags[*][ Key == 'Env' ] { Value == 'prod' }`, the binding read as `%env.Value == 'prod'`, a parameterized
   rule's parameter bound to the filtered query and a second filter through the binding, `%env[ Value == 'x' ]`, read
   the one object by the same test the inline spelling does, so over `Tags: { Env: dev, Value: { Ref: X } }` they are
   refused as `Tags[*][ Key == 'Env' ].Value == 'prod'` is, under `Key IN ['Env', 'Environment']` over `{ Environment:
   dev, Value: { Ref: X } }` too, and over `{ Team: a, Value: { Ref: X } }` and `{ Value: { Ref: X } }` all of them keep
   the empty selection; their refusal names the condition that failed, the entry the object holds beside the key read
   (`Env` over `{ Env: dev, Value: { Ref: X } }`), as the inline spelling's text does, and the record and the
   console carry its text as they carry the inline spelling's. Outside a filter predicate those spellings hold their
   refusal at the clause as the inline spelling does, so under `some` a passing sibling does not decide past it: `some
   %env.Value == 'prod'` over one function with map-shaped `{ Env: dev, Value: { Ref: X } }` tags and one with
   list-shaped `prod` tags fails as `some Resources.*.Properties.Tags[*][ Key == 'Env' ].Value == 'prod'` does. The
   moves are listed
   under "Behavior change in 3.2: a filter after `[*]` over one object that holds none of the keys the predicate
   compares against, with a query part after the filter" in [CLAUSES.md](CLAUSES.md). Map-shaped tags are the shape
   `AWS::Serverless::Function`, `AWS::SSM::Parameter`, `AWS::EKS::Cluster` and `AWS::EKS::Nodegroup`, `AWS::Glue::Job`
   and `AWS::Batch::JobDefinition` carry, where most resources carry a list of `{ Key, Value }` pairs.

   The cells the tests pin for this rule, each clause as written over the shape of the map it ran on; a row marked unpinned is a spelling the text uses that no test asserts.
   The shape column uses the labels [CLAUSES.md](CLAUSES.md#one-object-wildcard) defines (`one-object`, `collection`, `mixed`, `all-scalar`, `list`); `all-scalar, { ... }` writes the map's entries out where the verdict turns on which entry is present; `mixed collection` is a collection whose members differ in shape (map-shaped tags beside list-shaped ones); `n/a` marks a row whose clause fixes no map shape.

   | the clause | the map's shape | operator | verdict | notice | pinned by |
   |---|---|---|---|---|---|
   | `Properties.Tags[*][ Key == 'Env' ].Value == 'prod'` | all-scalar | == | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under `== 'prod'`") |
   | `Statement[*][ Principal == '*' ].Effect == 'Deny'` | one-object | == | SKIP | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "the same identity-policy statement with a part after the filter that reads `Effect`") |
   | `[ Action == '*' ].Condition exists` | one-object | exists | REFUSED | one-object refusal text (REFUSED marker "`[*]` then the filter read one object that has no `...`") | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a `NotAction` statement under `[ Action == '*' ].Condition exists`") |
   | `Statement[*][ Principal == '*' ][ Effect == 'Allow' ] empty` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a chained filter whose predicate names `Effect`, a key the object holds") |
   | `[ Principal == '*' ][ Sid == 'x' ]` | one-object | empty | REFUSED | one-object refusal text (REFUSED marker) | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a chained filter whose predicate names `Sid`, a key the object also lacks") |
   | `Resources.*[ Properties.PolicyDocument.Statement[*][ Principal.AWS == '*' ].Effect == 'Allow' ] empty` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "inside a predicate, `[ Principal.AWS == '*' ].Effect == 'Allow'`") |
   | `[ Principal.AWS == '*' ][ Effect == 'Allow' ] !empty` | one-object | !empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "inside a predicate, a chained filter `[ Principal.AWS == '*' ][ Effect == 'Allow' ] !empty`") |
   | `[ Action == '*' ].Condition exists` | one-object | exists | REFUSED | one-object refusal text (REFUSED marker) | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a `NotAction` statement under `[ Action == '*' ].Condition exists`") |
   | `[ Key == 'Env' ]` | all-scalar, `{ Env: dev }` | exists | PASS | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == 'Env' ]` | all-scalar, `{ Env: dev }` | !exists | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == 'Env' ]` | all-scalar, `{ Env: dev }` | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == 'Env' ]` | all-scalar, `{ Env: dev }` | !empty | PASS | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == 'Env' ]` | all-scalar, `{ Team: platform }` | exists | SKIP | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == 'Env' ]` | all-scalar, `{ Team: platform }` | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == 'Env' ]` | all-scalar, `{ Team: platform }` | !empty | FAIL | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key IN ['Env', 'Environment'] ]` | all-scalar | when %env !empty gate | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under a binding to `[ Key IN ['Env', 'Environment'] ]`") |
   | `[ Key != 'Env' ]` | all-scalar | .Value == 'prod' | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "two tags under `[ Key != 'Env' ]`") |
   | `[ Key == 'Owner' or Key == 'Env' ]` | all-scalar | .Value == 'prod' / empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == 'Env' Value == 'prod' ]` | list | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "list tags `dev` under `[ Key == 'Env' Value == 'prod' ] empty`") |
   | `[ Key == /^Env$/ ]` | all-scalar | when %env !empty gate | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == /Env/ ]` | all-scalar | when %env !empty gate / .Value == 'prod' | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `Tags[*][ Key == 'Env' ] exists` | all-scalar | exists | PASS | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under a bare `[ Key == 'Env' ] exists`") |
   | `[ Key == 'Env' Value == 'prod' ] empty` | list | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "list tags `dev` under `[ Key == 'Env' Value == 'prod' ] empty`") |
   | `[ Key == 'Owner' Value == 'Team' ] empty` | all-scalar | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags with no compared entry under `[ Key == 'Owner'  Value == 'Team' ] empty`") |
   | `[ Key NOT IN ['Env', 'Environment'] ]` | all-scalar | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags with no compared entry under `[ Key NOT IN ['Env', 'Environment'] ] empty`") |
   | `[ Key != 'Env' ] empty` | all-scalar, `{ Team: platform }` (no `Env` entry) | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags with no compared entry under a NEGATED bare `[ Key != 'Env' ] empty`") |
   | `[ Key != 'Env' or Value != 'prod' ] empty` | all-scalar | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `prod` under `[ Key != 'Env' or Value != 'prod' ] empty`") |
   | `[ Value == 'prod' Key != 'Env' ] empty` | all-scalar | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `prod` under `[ Value == 'prod'  Key != 'Env' ] empty`") |
   | `[ Key != 'Env' or Action != '*' ] empty` | all-scalar | empty | REFUSED | negation refusal text "while the object holds an entry named `Team` that the predicate's negated comparison of `Key` does not exclude" | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags with no compared entry under `[ Key != 'Env' or Action != '*' ] empty`") |
   | `Env[*][ Name != 'x' ] empty` | all-scalar | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "an env-var map keyed by name under `Env[*][ Name != 'x' ] empty`") |
   | `[ Values != 'x' ] empty` | all-scalar | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "an env-var map keyed by name under `Env[*][ Values != 'x' ] empty`") |
   | `[ Action != '*' ]` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object `NotAction` statement under `[ Action != '*' ] empty`") |
   | `[ Value != 'platform' ]` | all-scalar, `{ Team: platform }` | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags with no compared entry under a negation on the value") |
   | `[ Value != 'platform' ]` | all-scalar, `{ Env: dev }` | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under `[ Value != 'platform' ] empty`") |
   | `Statement[*][ Action != '*' ] empty` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object `NotAction` statement under `[ Action != '*' ] empty`") |
   | `[ Key == 'Env' Value != 'prod' ]` | all-scalar | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags with no compared entry under `[ Key == 'Env'  Value != 'prod' ] empty`") |
   | `Statement[*][ Principal == '*' ] empty` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "an identity-policy statement under `[ Principal == '*' ] empty`") |
   | `[ Action == '*' ] empty` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a `NotAction` statement under `[ Action == '*' ] empty`") |
   | `[ Resource == '*' ] empty` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a trust-policy statement under `[ Resource == '*' ] empty`") |
   | `[ Principal.AWS == '*' ] empty` | one-object | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "the same statement under `[ Principal.AWS == '*' ] empty`") |
   | `Resources.*[ Properties.Tags[*][ Key == 'Env' ].Value != 'prod' ] empty` | all-scalar | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "select the violators, assert none") |
   | `Tags[*][ Key exists ] !empty` | all-scalar | !empty | PASS | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "`[ Key exists ] !empty` over map tags") |
   | `Tags[*][ Key == 'Env' ].Value == 'prod'` | all-scalar | == | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under `== 'prod'`") |
   | `rule r when %env !empty { %env.Value == 'prod' }` under `let env = Resources.*.Properties.Tags[*][ Key == %wanted ]` | all-scalar | when %env !empty gate | REFUSED | the predicate compares against `%wanted`, a name bound outside the predicate (query-bound); the literal `let wanted = 'Env'` is FAIL with the twin's notice and no refusal | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Key == %w ] !empty` where `%w` is the capture of an earlier clause | all-scalar | !empty | FAIL | the predicate compares against `%w`, a name bound outside the predicate | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under `[ Key == %w ] !empty`") |
   | `%t IN ['Nope']` | n/a | IN | PASS (the captured key is compared, not the block's `let t = 'x'`) | shadowing notice ("shadows a `let t` of an enclosing scope ... Rename one of them") | eval_tests.rs:a_shadowed_block_let_is_read_as_the_captured_key_in_the_documented_spelling |
   | `let env = Resources.*.Properties.Tags[*][ t \| Key == 'Env' ]` | all-scalar | let; %t.Value == 'prod' read later | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under a filter capture read later") |
   | `Tags[*][ t \| Key == 'Env' ] exists` (the first clause of a rule whose second clause is `%t.Value == 'prod'`) | all-scalar | exists | PASS for the `exists` clause (the cell's asserted FAIL is the whole rule's, from `%t.Value == 'prod'` over `dev`) | the verdict is the twin's; no refusal | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under a filter capture and a bare `exists` in the filter's own clause") |
   | `let n = count(Resources.*.Properties.Tags[*][ Key == 'Env' ])` | all-scalar | count() | unpinned (no test asserts this cell) | none | none |
   | `Tags[*][ Key == 'Env' ] { check(this) }` | all-scalar | block | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under the block form `{ check(this) }`") |
   | `{ this[*] { Value == 'prod' } }` | all-scalar | block | FAIL | none | eval_tests.rs:every_delivery_path_of_a_body_read_refuses_as_the_inline_spelling_does (case "the nested block over `this[*]`") |
   | `Statement[*][ Principal == '*' ] { Effect == 'Allow' Condition exists }` | one-object | block | REFUSED | one-object refusal text "and `Condition` is read from that selection after the filter, a key the object also lacks" | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement under `[ Principal == '*' ] { Effect == 'Allow'  Condition exists }`") |
   | `this[ Effect == 'Allow' ] empty` | one-object | empty | REFUSED | held-only refusal text "from an object holding nothing beside the keys read, the shape the predicate was ..." | eval_tests.rs:every_delivery_path_of_a_body_read_refuses_as_the_inline_spelling_does (case "every key read, one through a second filter in the body") |
   | `Statement[*][ Principal == '*' ][ Effect == 'Allow' Action == '*' Resource == '*' ]` | one-object | empty | REFUSED | held-only refusal text "from an object holding nothing beside the keys read, the shape the predicate was ..." | eval_tests.rs:a_held_only_body_answers_as_the_inline_chained_filter_does; unpinned: the fn reads this clause as the equality reference and asserts no status of its own |
   | `{ let l = to_lower(this) let m = %l[*] %m == 'x' }` | one-object | block | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `[ Effect exists %flag == true ]` | one-object | chained filter | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `[ Sid == 'x' or %flag == true ]` | one-object | empty | REFUSED | one-object refusal text "and `[ Sid == 'x' or %flag == true ]` is read from that selection after the filter" | eval_tests.rs:a_clause_nested_in_the_body_is_judged_on_its_own_reads (case "the inline chained `[ Sid == 'x' or %flag == true ] empty`") |
   | `some Resources.*.Properties.Tags[*][ Key == 'Env' ] { Value == 'prod' }` | mixed collection | some + block | PASS | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "two functions, one map-shaped and one list-shaped, both `prod`, under `some` and the block form") |
   | `Statement[*][ Principal == '*' ].Condition exists` | one-object | exists | REFUSED | one-object refusal text (marker "and `Condition` is read from that selection after the filter") | eval_tests.rs:a_deferred_lacks_keys_refusal_is_recorded_as_the_inline_spellings_is (case "the control") |
   | `Statement[*] { when Principal == '*' { Condition exists } }` | n/a | when gate in a block | unpinned (no test asserts this cell) | none | none |
   | `[ Key == /^(?!aws:)/ ]` | all-scalar | when %env !empty gate | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under a binding to `[ Key == /^(?!aws:)/ ]`") |
   | `Statement[*][ Sid == /^(?!aws:)/ ].Effect == 'Deny'` | one-object | == | unpinned (no test asserts this cell) | none | none |
   | `Tags[*][ Key == /^[A-Za-z]+[0-9]$/ ] empty` | all-scalar | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `{ Env1: dev }` under a bare `[ Key == /^[A-Za-z]+[0-9]$/ ] empty`") |
   | `Tags[*][ Key == /^[A-Z][a-z]+$/ ] empty` | all-scalar | empty | FAIL over `{ Env: dev }`; PASS over `{ Env1: dev }` | the verdict is the twin's over `{ Env: dev }`; none over `{ Env1: dev }` | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `Tags[*][ Key == /^[A-Za-z0-9]+$/ ] empty` | all-scalar | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ Principal == '*' or Sid == /^\w+$/ ]` | one-object | empty | REFUSED | every-key refusal text "the predicate compares `Sid` against matches every key" (and EVERY_KEY_EMPTY), absent "the predicate compares `Principal` against matches every key" | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement under `[ Principal == '*' or Sid == /^\w+$/ ] empty`") |
   | `[ Sid == /^\w+$/ ] empty` | one-object | empty | REFUSED | every-key refusal text "so the empty selection would pass by holding nothing, not by what the object holds" | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement under a bare `[ Sid == /^\w+$/ ] empty`") |
   | `[ NotResource == /.+/ ] empty` | one-object | empty | unpinned (no test asserts this cell) | none | none |
   | `[ Sid == /^\w+$/ ] !exists` | one-object | !exists | SKIP | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement under a bare `[ Sid == /^\w+$/ ] !exists`") |
   | `Resources.*[ Properties.PolicyDocument.Statement[*][ Sid == /^\w+$/ ] is_struct ] empty` | one-object | is_struct | REFUSED | every-key operator refusal text "refused under `is_struct` inside a filter predicate" | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement without `Sid`") |
   | `let env = ...[ Key == /^[^T]/ ]` with a `when %env !empty` gate | all-scalar | when %env !empty gate | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `Key IN ['Env']` | all-scalar | .Value == 'prod' | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `Key IN ['Env', 'Environment']` | all-scalar | .Value == 'prod' | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `let env = ...[ Key == /^[A-Za-z]+$/ ]` with a `when %env !empty` gate | all-scalar | when %env !empty gate | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `Tags[*][ Key == /[Ee]+/ ] exists` | mixed | exists | SKIP | none | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure |
   | `Statement[*][ Sid == /.+/ ].Effect == 'Deny'` | one-object | == | SKIP | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement under `[ Sid == /.+/ ].Effect == 'Deny'`") |
   | `Statement[*][ Sid == /^[A-Za-z0-9]+$/ ].Effect == 'Deny'` | one-object | == | SKIP | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement under `[ Sid == /^[A-Za-z0-9]+$/ ].Effect == 'Deny'`") |
   | `Statement[*][ Sid == /^[A-Za-z]+$/ ] exists` | one-object | exists | SKIP | none | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure (case "statement `{ Effect: Allow }` under a bare `[ Sid == /^[A-Za-z]+$/ ] exists`") |
   | `Tags[*][ Key == /^[A-Za-z]+$/ ] exists` | mixed | exists | SKIP | none | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure (case "mixed map under a bare `[ Key == /^[A-Za-z]+$/ ] exists`") |
   | `Statement[*][ Sid == /^\w+$/ ] empty` | one-object | empty | REFUSED | every-key refusal text EVERY_KEY_EMPTY | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement under a bare `[ Sid == /^\w+$/ ] empty`") |
   | `[ Key == /^[A-Za-z]+$/ ] empty` | mixed | empty | REFUSED | every-key refusal text EVERY_KEY_EMPTY | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure (case "mixed map under a bare `[ Key == /^[A-Za-z]+$/ ] empty`") |
   | `Tags[*][ Key == /^[Ee][Nn][Vv]$/ ] exists` and `empty` over the mixed maps | n/a | n/a | REFUSED | own-key refusal text NAMES_ENV "the object holds an entry named `Env`, a value the predicate compares `Key` ..." | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure |
   | `Tags[*][ Key == /^[Ee][Nn][Vv]$/ ] empty` and `exists` over MAP_TAGS_MIXED and MAP_TAGS_ENV_BOTH | mixed | exists / empty | REFUSED | own-key refusal text NAMES_ENV | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure |
   | `Statement[*][ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists` and `empty` over the `{ Effect: Allow }` statement | one-object | exists / empty | REFUSED | own-key refusal text NAMES_EFFECT "the object holds an entry named `Effect`, a value the predicate compares ..." | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure |
   | `Tags[*][ Key == /^[Ee][Nn][Vv]$/ ] exists` | mixed | exists | REFUSED | own-key refusal text NAMES_ENV | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure (case "mixed map `{ Env: { Ref }, Team: platform }` under a bare `[ Key == /^[Ee][Nn][Vv]$/ ] exists`") |
   | `Tags[*][ Key == /^[[:alpha:]]+$/ ] exists` | mixed | exists | REFUSED | REFUSED pinned by the cited case; the NAMES_ENV text is not asserted until a later revision | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure (case "mixed map `{ Env: dev, ENV: { Ref } }` under a bare `[ Key == /^[[:alpha:]]+$/ ] exists`") |
   | `Statement[*][ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists` | one-object | exists | REFUSED | own-key refusal text NAMES_EFFECT | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure (case "statement `{ Effect: Allow }` under a bare `[ Sid == /^[Ee][Ff][Ff][Ee][Cc][Tt]$/ ] exists`") |
   | `[ Sid == /^\w+s?$/ ] exists` | one-object | exists | REFUSED | own-key refusal text NAMES_EFFECT | eval_tests.rs:a_name_regex_over_a_one_object_map_holding_a_non_scalar_entry_is_read_by_its_structure (case "statement `{ Effect: Allow }` under a bare `[ Sid == /^\w+s?$/ ] exists`") |
   | `[ Key == /^(?!aws:)/ ] exists` | mixed | exists | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `[ Key == /^[A-Za-z]+$/ ] !empty` | all-scalar | !empty | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `[ Sid == /^E/ ].Effect == 'Deny'` | one-object | == | REFUSED | own-key refusal text "the object holds an entry named `Effect`, a value the predicate compares `Sid` against" | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "a one-object statement holding `Effect`, `Env` and `Action` under `[ Sid == /^E/ ].Effect == 'Deny'`") |
   | `Tags[*][ Key == 'Env' ] { Value == 'prod' }` | all-scalar | block | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under the block form `[ Key == 'Env' ] { Value == 'prod' }`") |
   | `%env[ Value == 'x' ]` | all-scalar | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `Team` and `Value` under `%env[ Value == 'x' ] empty`") |
   | `some Resources.*.Properties.Tags[*][ Key == 'Env' ].Value == 'prod'` | mixed collection | some + == | PASS | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "two functions, one map-shaped and one list-shaped, both `prod`, under `some` and the inline spelling") |
   | `Properties.Tags[*] { Key exists }` | n/a | block | unpinned (no test asserts this cell) | none | none |
   | `Statement[*] { when Principal exists { Principal.AWS != '*' } }` | one-object | when gate in a block | SKIP | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "the presence-guarded spelling is not applicable over the statement with no principal") |
   | `Statement[*].Principal.AWS != '*'` | n/a | != | unpinned (no test asserts this cell) | none | none |
   | `[ Key == 'Env' ] exists` | all-scalar | exists | PASS | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under a bare `[ Key == 'Env' ] exists`") |
   | `[ Key != 'Env' ] empty` | all-scalar, `Env` alone | empty | PASS | none | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under `[ Key != 'Env' ] empty`") |
   | `[ Value == 'prod' ] empty` | all-scalar | empty | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `{ Team: prod }` under `[ Value == 'prod' ] empty`") |
   | `[ Key == 'Env' ].Env` | all-scalar | .Env | unpinned (a near spelling is pinned, this one is not) | none | none |
   | `[ Key == %wanted ]` | all-scalar | when %env !empty gate | REFUSED | the predicate compares against `%wanted`, a name bound outside the predicate | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused |
   | `[ t \| Key == 'Env' ]` | all-scalar | let then %t.Value == 'prod' | FAIL | the verdict is the twin's | eval_tests.rs:a_filter_after_a_bracket_wildcard_over_one_object_holding_none_of_the_predicates_keys_is_refused (case "map tags `dev` under a filter capture read later") |

   > **Workaround**: write the predicate over a key the object holds, read the key itself (`Properties.Tags.Env ==
   > 'prod'`, `Properties.Tags.Key exists`, `Properties.Tags[*] { Key exists }`), guard a key that may be absent with a
   > presence check (`Statement[*] { when Principal exists { Principal.AWS != '*' } }`, not applicable at exit 0 where
   > the key is absent and failing where the principal is `*`, over one object and a list alike;
   > `Statement[*].Principal.AWS != '*'` fails on the missing key in both forms), guard a comparison that reads a second
   > optional key the same way (`Statement[*] { when Principal == '*' { Condition exists } }` in place of
   > `Statement[*][ Principal == '*' ].Condition exists`), or write the list in the template.

   Since 3.2 the refusals of this entry are the fallback, not the first reading: a PAIR-SHAPED predicate (every
   clause reads `Key` or `Value`, bare or as `this.Key` / `this.Value`, against a literal or nothing; a `%name` whose
   binding is a literal at the filter, `let wanted = 'Env'` or a called rule's parameter given a literal, counts as the
   literal) over a map whose entries are all scalars is decided by the map's `{ Key, Value }` list twin `[ { Key:
   <name>, Value: <value> }, ... ]`, the predicate evaluated over each pair by the engine itself (`==`, `IN` against a
   list, a regex, `exists` and `empty` by a walk that agrees with the evaluator by construction; everything else, `IN`
   against a string haystack and a regex the engine could not run included, by the evaluator, which fails closed), the
   kept pairs the selection, so `Tags[*][ Key == 'Env' ].Value == 'prod'` over `{ Env: dev }` fails on `dev` with no
   refusal, `[ Key == 'Env' ] exists` passes, `[ Key != 'Env' ] empty` over `{ Env: dev }` passes (the twin excludes the
   pair), `[ Value == 'prod' ] empty` over `{ Team: prod }` fails (a selecting clause on `Value` alone, which the
   previous release's reading passed vacuously), `[ Key IN 'Environment' ] exists` over `{ Env: dev }` passes (the haystack the
   evaluator reads; a walk that compared the two for equality would read it as not applicable), and a filter the
   twin keeps nothing of (`[ Key == 'Env' ]` over `{ Team: platform }`) leaves the empty selection with no refusal, its
   `.Value` read not applicable and its block body never run, as over the list. A map that holds neither `Key` nor
   `Value` as a key of its own is the twin's whatever the one-object reading kept of it: such a map can be kept only by
   a clause that holds by absence, so `[ Value empty ] empty` and `[ Key !exists ] empty` over `{ Env: dev }` pass as
   the twin does, and `[ Key == 'Env' or Key !exists ].Env == 'dev'` fails on
   the kept pair's missing `Env` as it fails over the list (a reading that answered the absence arm from the map's own
   `dev` would pass); a map that holds `Key` or `Value` may be one pair written as a map: one whose keys are exactly the
   two fields of a pair, `{ Key, Value }` or `{ Name, Value }`, and that holds every pair field the predicate reads and
   the key read after the filter is the one record the rule was written for, and what the one-object reading decided of
   it, nothing kept included, is the answer, as over the one-element list, the twin unasked (`[ Value != 'x' ] empty`
   over `{ Name: InstanceId, Value: x }` keeps nothing and passes as the list does, where a twin asked would keep the
   pair `{ Key: Name, Value: InstanceId }` under the negation and fail it); a map of tags holding a tag named `Value` or
   `Key` beside other tags is not the record and the twin decides it (`[ Value == 'public' ] empty` over `{ Value:
   internal, Exposure: public }` fails on `{ Key: Exposure, Value: public }` as over its list; a reading that took any
   map holding the fields the predicate reads for the record passed it with nothing kept); one that holds one of the
   two and lacks a field the predicate reads, or is read after the filter by a key it has not, is kept by a predicate as
   the author's selection and the twin is asked only when nothing was kept. Whatever follows the filter reads the
   pairs as it reads a list's elements, a key the pair has not included: `[ Key == 'Env' ].Env !exists` passes in the
   inline spelling as in the block form and through a binding. A capture in the filter (`[ t | Key == 'Env' ]`) binds
   the kept pairs, so `%t.Value` is `dev`. Each pair reports at its entry's own path, `/Resources/Fn/Properties/
   Tags/Env`, the node the template has (a synthesized `<map>/<index>` or `<map>/<index>/Key` path would collide with a
   key named `"0"`). One notice per FILTER SITE whose twin kept a pair, written for the first such map the
   filter met, names the filter as written, the map's path and its KEYS (never a value: `Variables[*][ Key ==
   /PASSWORD/ ]` over `{ DB_PASSWORD: ... }` would otherwise write the secret to the error stream; a key holding a line
   feed is escaped) and `<X>.<key>` as the way to read the map itself, with no per-map count (the one line stands for every map
   the filter meets); a filter whose
   twin keeps nothing of every map it meets is not announced. What this entry's refusals still
   cover: a predicate that is not pair-shaped (`Sid`, `Action`, `Principal`, `Env`, `Condition`, a key with a part after
   it, a `this` comparison, a comparison against a document query or a function call, a `when`, a block or a rule call in
   the predicate), a map with a non-scalar entry (read first, so such a map keeps this reading whatever the predicate
   compares against), and a predicate that compares against a `%name` that holds no literal at the filter (a capture
   of the rule under evaluation, a parameter given a query, a query-bound `let`, a key a block merged up), whose bare
   read is refused, fail closed, since the name's value is not fixed at the filter. One limit stays: a function over the
   selection (`count(...)`) counts the pairs it is handed, which the kept pairs are.

17. <a name="member-notice-value-before-the-wildcard"></a> The member notice for a filter after `[*]` over a map of members names the
    value the released engines asked the predicate of, which Guard reads off the map's own path. It names it where the path says
    which value that is, and says nothing where it cannot: a filter, a map-key filter or a `%variable` between the last `.*` and the
    wildcard (`Resources.*.Properties.Rules[ Kind == 'x' ].Sub[*][ K exists ]`, `Cfg[ keys == 'Alpha' ].Sub[*]`), a key that is not
    the component the path holds, and a root that is not a prefix of the map's path on a component boundary. The released
    3.1.12, 3.2.0 and 3.2.1 agree on those shapes (they asked the `.*` member, or, after a key filter that selected nothing, no
    candidate at all), so a notice naming another value would be a false sentence. A filter over members that all hold the keys
    it names, with no clause that holds by absence, is skipped on the map alone only when the value before the wildcard holds none
    of those keys (the document before `Resources[*][ Type == 'X' ]`): the value is read by reference, never cloned, for that
    question. Where it holds one (`Resources.*.Properties.Rules[*][ Type == 'AWS::S3::Bucket' ]` asked of the bucket, or `Type ==
    'AWS::S3::Bucket' or Name == 'r'` over `Rules: { A: { Type: X }, B: { Name: q } }`), the released engines could hold the
    predicate on that value through its own key and select it whole where nothing is kept now, so it is probed once per site and
    map, and a hold is announced by the key the predicate held through (`Type`), which the members hold each for themselves; a hold
    is stated as one by absence only for a predicate that can hold by absence. A `%param` in the predicate keeps the
    site from recording a quiet verdict, so it is probed again on every evaluation of the site (no deep copy of the value: the walk
    under `Resources.*` has the resource as its root). Separately, `labels.*[ this !empty or env exists ] empty` over
    `{ team: '', tier: web }` passes at exit 0 (every scalar passed over, nothing selected) while `labels.*[ this !empty ] empty`
    is refused: under `.*`, adding a disjunct that names a key can select less. It is pinned as it reads, and written
    `labels.*[ env exists ] empty` when that is what is meant.

18. <a name="second-refusal-behind-a-let-bound-selection"></a> A comparison that reads a `let`-bound selection holding a
    refusal's marker is raised at the bare read of the binding, before any pair is compared, on that one refusal's
    sentence alone, unnumbered. A second refusal the comparison would have met among its values does not reach the
    raised text: `when some %names NOT IN %x` with `%names` a key filter's selection over map-shaped tags (the filter's
    one marker, bound by `let`) and `%x` the keys a filter captured beside an own-key refusal's marker meets two
    refusals, and the raise names the key filter's alone; the own-key refusal is registered by the walk that delivered
    its marker and stands in that walk's records, in no error of this clause. Two refusals inside one binding (`when
    Resources.B.Type IN %names` with two map-tagged functions, one marker each, and nothing resolved in `%names`) are
    raised on the first note's text, and that one text is registered; the second refusal is unreported there. The
    numbered raise that names both refusals in registration order (`(1) ... (2) ...`) is reached where two refusals
    stand among one comparison's values, which a `let`-bound selection delivers inside a filter predicate (the same
    two-refusal `%names` under `[ Properties.Tags[*] IN %names ] empty` compares nothing and is raised on both, with
    both sentences registered) and never at a bare read outside one. Pinned as it reads by
    eval_tests.rs:a_raise_beside_two_refusals_names_both_in_registration_order.

19. <a name="not-in-with-a-marker-on-the-left"></a> A refusal to compare kinds beside a refusal's marker is a decided no
    of its own kind under `!=`: `when Vals.Port != %x` with `Port: 22` and `%x` holding string keys beside the marker
    refuses `22` against each key on kinds, the gate declines on that decided no, each refused pair's record carries the
    kinds sentence as a refusal, and the refused-read line reads "was decided by a value of another kind". Under `NOT
    IN` beside a marker on the RIGHT, a refusal of kinds is unknown by design: membership refuses a value only when no
    entry can be compared with it, and the entry the marker hides may be the comparable one, so `22 NOT IN {'ssh', ?}`
    is unknown where `22 NOT IN {'ssh'}` is decided. Under `NOT IN` with the marker on the LEFT, the kind arm does not
    decide the shape at all: `%names NOT IN Haystack` with `%names` a key filter's selection over a bucket's list-shaped
    tags (the tag map `{ Key: Env, Value: allowed }`) and a function's map-shaped tags (the filter's refusal marker),
    against a string the document holds, is raised on the marker alone (as a `when` condition the rule fails closed;
    asserted, the clause fails on the marker's pair), one refusal registered, no refused-read line in the kind wording
    and none in either resolved wording (the two readings the rows take), and no kinds sentence recorded for the map
    against the string. Whether the left-marker negated membership should be
    decided by the kind refusal is open; the shape is pinned as it reads by the two `NOT IN` rows of
    eval_tests.rs:a_refusal_to_compare_kinds_beside_a_marker_is_worded_as_its_own_refusal, which go red when the
    reading changes.

20. <a name="plain-marker-report-arms-disagree"></a><a name="plain-marker-record-flag-by-side"></a> Whether a PLAIN marker's comparison record is flagged a refusal
    depends on which side of the comparison the marker stands on; the choice that stays open is named at the end of
    this item. The console's two report arms word a PLAIN marker (a filter
    predicate's entry left undecided by a raise that was no refusal, carried in a capture) the SAME way on either
    side of the comparison, as a value that "could not be decided", the undecidable wording, read off the operand's
    own kind and not off the record's flag: with the marker on the LEFT (`%b != %x`, `%b` the marker, `%x` the keys
    and a refusal's marker) the arm that renders a failing comparison's `from` no longer reads it as "the value to
    compare from could not be read", the refusal wording the flag alone once read into it, and with the marker on the
    RIGHT (`%x != %b`) the arm that renders `to` no longer reads it as a property the template lacks ("to compare to
    is missing"), the wording of an absence, for a key the document holds. The comparison's own records of the
    marker's pairs still differ by spelling. In `%b != %x` the marker is the one left-hand value, so it has ONE
    record, the marker as `from`, whose message carries the refusal's sentence beside the marker's own and whose flag
    reads `refusal: true`: the `LhsUnresolved` arm flags a left marker's record by the refused read among the
    right-hand values it was compared against (`a_refused_read_on_the_right`), while the report arm reads the
    operand. In `%x != %b` the marker is paired with each key, so it has one record per key, the marker as `to`, each
    carrying the marker's own sentence and flagged `refusal: false`: the `RhsUnresolved` arm flags a right marker's
    record by the marker's OWN kind (`refused_read_text`), and the refusal's marker, now on the left, has its own
    record flagged `true` and is reported with the refusal wording for its own side. One choice stays open: whether a
    record should be flagged by the operand it holds alone or by its right-hand company as well (the flag is the
    console's print-whole switch). No verdict, exit or registry entry moves with it (the clause FAILs in both
    spellings, the gate raising on the refusal); the shape is pinned as it reads by a test which selects the
    comparison's own records by the comparison and by the marker operand (never by context or by `any` over the
    rule's records, which an earlier form of the cell did, passing on records of the unrelated `Cfg[ x | Kind == 'k' ]`
    clause), reads each pair's flag and message, and reads the report's sentences on both sides, so it goes red when
    either arm's wording or either spelling's flags change
    (pinned by `eval_tests.rs:a_plain_left_marker_beside_a_right_refusal_is_reported_as_undecided_on_both_sides`).

21. <a name="a-map-filters-capture-holds-the-key"></a> A filter's capture over a MAP holds the KEYS the filter kept, not the
    members: `Sub[ s | Name exists ]` over `Sub: { S1: { Name: 'n' } }` binds `%s` to the string `S1`, so `%s.Name == 'n'`
    reads `Name` off a string, the retrieval fails ("Attempting to retrieve from key Name but type is not an struct type
    at path ..."), and the clause is decided by that absence: an assertion FAILS, a filter predicate deselects the entry
    (a disjunct spelled this way never decides its `or`), a `when` condition is not applicable. Read the member through
    its parent, `Sub.%s.Name == 'n'`, the way `Resources[ id | ... ]` is read back as `Resources.%id.Type`. A filter over
    a LIST (`Rules[ r | Action == 'allow' ]`) binds the member itself, so `%r.Name` reads there. Not a defect, the
    documented binding; recorded because the two spellings read alike and the fail-closed verdict names a retrieval, not
    the binding (pinned by `eval_tests.rs:a_map_filters_capture_holds_the_key_so_a_field_read_off_it_fails_closed`), in all
    three roles, each beside its `Sub.%s.Name` control: the assertion's FAIL with the retrieval's reason on record, the
    filter predicate's deselected entry (`!empty` over the filter fails), and the `when` condition not applicable; the
    rows go red if `%s.Name` ever decides a clause.

22. <a name="a-not-over-a-refusal-only-fail-fails-closed"></a> A reference's `not` over a rule whose FAIL rests on reads
    it could not decide FAILS closed rather than passing. `rule main { not check }` with `rule check { some %y NOT IN %m
    }` over a `%m` holding a key filter's refused marker: `check` fails at its leaf on the refusal (an assertion fails
    closed on a refused read), and this evaluator before the change inverted that FAIL into `main`'s PASS, a verdict the
    refusal manufactured; it now answers FAIL for `main`. Whether a FAIL rests on undecidables alone is decided by the
    STRUCTURE of the rule's folds, each answering its FAIL with a basis combined from its branches' (a decided no, or
    the undecidable reads the FAIL rests on): a conjunction's FAIL is decided
    when any failing conjunct's is (`AND(no, unknown)` is `no`, so `some %y NOT IN %m  Maps.Nope exists` is a plain no and
    `not check` passes as before, the refused read's line reading "passed by the negation of a rule that failed"); a
    disjunction's or a `some` block's FAIL is decided only when every failing branch's is (`OR(no, unknown)` is unknown,
    so `Maps.Nope exists or some %y NOT IN %m` and a `some` block with one refused entry are refusal-born and `not check`
    fails closed). The basis travels inside the FAIL (a judged answer is a PASS, a SKIP or a FAIL with its basis, so no
    PASS or SKIP carries one) and so in the rule-status cache, never through the refused-read entries a quiet probe or a
    measurement leaves empty, so a gate over `not check` read under a measurement answers as the real run does; every site
    that turns an undecidable into a strict FAIL names it, a spent regex budget's marker and the block arm's own-key
    refusal included, which note no refused read. Two record shapes: in a rule body the fail-closed `not` is a FAIL whose
    own record says why, in one of two variants chosen by what the basis holds: flagged a refusal and naming the read(s)
    where the FAIL rests on one ("the negated rule [check] failed only on reads it could not decide, so the negation
    fails closed rather than passing: ..."), unflagged and naming the undecidable's own text where it is no refusal, a
    spent regex budget's marker or a type the operator has no answer for ("... rather than passing: <the text>"; only a
    FAIL that carries neither a read nor a text says the undecided reads are reported where the rule met them); the
    author's `<< >>` message on the reference rides in the record's own field; and either variant writes NO
    refused-read line, since failing closed is acting on the refusal and "was not raised" would be false of it; as a
    `when` condition the negated rule runs in the gate role, where every undecidable leaves it as a raise that reaches the
    reference before any negation (no gate-role or filter-role `not` ever meets an undecidable-born FAIL; a debug build
    asserts it, and a release build in which that ever broke would raise the undecidable as the refusal it is, carrying
    the read's token, rather than answer a status), so `rule r when not check { .. }` fails `r` closed on its condition
    rather than opening or skipping the block, the same answer "raise the negation" would have given, reached by the
    rule's own raise. One exception to the conjunction rule, decided by one test in every role: a block whose body
    read the empty selection a one-object filter left, and was refused there, has a body whose decided no holds under
    the reading of the filter that kept an element and not under the reading that kept none, so the block's FAIL is
    decided exactly when its judgement over its other values alone equals its judgement over them plus that failure,
    the status and the basis of a FAIL alike, and rests on the refused read otherwise. Alone, the readings agree only
    under `not empty` (without it the other reading is SKIP, so a `not` over the rule would answer PASS under one
    reading and SKIP under the other, and the FAIL rests on the refused read instead, failing the `not` closed, where
    this evaluator before the change inverted the body's no into a PASS); beside sibling values a `some` block agrees
    unless every sibling skips (`not check` passes with the read's line where the siblings fail), an every-entry block
    agrees where a sibling fails on a decided no and disagrees where every sibling passes or where every failure rests
    on an undecidable (`not check` fails closed naming every read; as a `when` condition the block raises and the gated
    rule fails closed, where it was reported not applicable before); a sibling the block could not decide (a raise it
    holds, another refused selection whose body is undecidable) agrees with nothing, so the block raises unless another
    sibling decides it (a sibling that fails on a decided no decides an every-entry block); a refused selection whose OWN
    body is undecidable over it (refused whole by the keys the body read together, or raising over the read it refused,
    whichever error the body's conjunction held first) decides nothing either way and is judged by its siblings in both
    roles, so a sibling that passes decides a `some` block and one that fails on a decided no decides an every-entry
    block, each with the block's own line, and nothing decided, the block fails closed or raises on that read (see
    `eval_tests.rs:a_blocks_pending_refused_selection_is_settled_at_every_exit_in_both_roles (cases "HO", "PO", "PF", "PEp", "POp", "HOp", "HSa", "HSs", "HSp")`;
    an earlier build returned at once on such a body beside siblings, so the clause spelling's order inside the body
    decided whether the siblings were consulted; the gate's verdict no longer depends on that order (a `when`
    condition reads both kinds the block can raise as three-valued, and a sibling condition that decided no decides
    past either), and the record reads the same in both clause orders: with no sibling deciding the block and a
    budget marker's comparison also held (a sibling's `%m !empty` over a map whose key spent the engine's budget), the
    fold ranks a refusal, a comparison carrying a refusal's token or an `Unevaluatable` whose text the registry holds,
    above a held error that is none, whichever was held first, so a body whose FIRST held error is that marker's raise
    (which re-raises the refused read as a comparison carrying its token) and a body whose first held error is the
    refused read itself (which re-raises the plain refusal) both leave the condition record flagged a refusal and
    naming the read, where the plain refusal used to lose to the comparison already held and the record was unflagged
    and named no read. The ranking moves the text and keeps the held error's variant and token, since a block reads
    the variant (a comparison is the value's answer for the siblings to decide, a plain `Unevaluatable` ends the
    block at once), and takes the text only outside a filter predicate run and only when the arriving error is a
    refusal by its token or by its text (a sentence the registry holds): a tokened refusal whose text no one registers
    (the key filter's wrap of a numbered text) leads the raise, with the held cause after it cut to a part, and the
    joined text is registered under the token so the record is flagged as the block's mark for the same pair is,
    since a held `Unevaluatable` carries no token to flag it by (the registered join is an entry that is no read of
    its own; flagging by a token on a comparison variant is the alternative, and it moves what a block reads). A
    later registered refusal over a held registered refusal is ranked by token, in either order and either
    variant, and the higher-ranked one replaces the other whole, so a joined text holds one refusal sentence at
    most; a tokened text that nobody registers leaves a held registered refusal as met. That leaves one pair
    order-dependent: a registered refusal held as a plain `Unevaluatable` keeps its place against an unregistered
    tokened wrap that arrives later, whichever of the two was minted later, while the same registered refusal
    held as a comparison with no token, or the wrap held first, is ranked by minting, so the later-minted of the
    two stands (the wrap's join, when the wrap arrived over a plain cause). The raise names one of the two
    refusals either way. Inside a
    predicate run a held `Unevaluatable` whose text the registry does not hold keeps its text, since the run
    classifies its entry's marker by it. A held comparison inside a predicate run meets an arriving registered refusal as a pair: a
    refusal minted inside the run replaces the held text, token and text together, so the entry is the run's refused
    one, and a refusal minted before the run does not make it the run's, as for two comparisons.
    Where a plain `Unevaluatable` is held first and a refusal arrives, the error handed up carries the refusal's text
    and no token. The held error's own text, a converter's cause, is the one dropped where the refusal's text is a
    registered sentence. Inside a predicate run the
    order of the conjuncts still decides which form the failure takes (a refusal conjunct before a budget comparison
    fails the whole filter as an error, the other order leaves a per-entry marker). The rows
    that pin the arms are `the_pair_rule_keeps_the_latest_refusal_whole_else_the_first_reason_with_no_token`,
    `a_budget_comparison_held_in_a_predicate_run_meets_an_arriving_refusal_as_a_pair` and
    `a_tokened_refusal_arriving_after_a_plain_error_is_named_whether_or_not_its_text_is_registered`, and cases "OM",
    "OR", "OMc" and "ORc" of `a_blocks_pending_refused_selection_is_settled_at_every_exit_in_both_roles` (the read's line is written once in either order where the sibling condition decides past the raise,
    "was decided by a sibling clause's failure", since the refused selection's entry is pushed into the block's
    absorbed entries whichever kind the block raises and the raise hands them up; and a body with NO sibling, which
    holds nothing before its own error, hands the gate its own kind in both orders, the record flagged and naming the
    read either way, cases "OMl" and "ORl"); the per-value
    mark such a body leaves, where it raised a marker of
    another text, is written after the siblings' records, where it was written at once, so the record tree and
    `-o json` list it after them); a refused selection with no
    value beside it is judged after every selection has run, as a lone selection is: beside a second refused selection
    whose body is undecidable the siblings are undecided, so `not check` fails closed and the gate fails closed in
    either map order. A selection is refused by a read of a key the object LACKS; a key the object HOLDS (`Effect`
    over a one-object statement) is read as nothing over the refused selection, as the dotted spelling
    `Statement[*][ Principal == '*' ].Effect == 'Deny'` reads it, so a clause on it is not applicable and a `when` in
    the body gated on it reads nothing and leaves the value not applicable, never refused (the "GKk"/"GKek" rows);
    the chained-filter spelling `[ Sid exists  Effect == 'Deny' ] !empty` is refused only when every key it names is
    lacking (the second-filter rule in `docs/CLAUSES.md`), so naming the held `Effect` it is not refused and keeps
    nothing, the empty selection its list twin is, and its `!empty` fails where the block fails closed (the
    "E1nk"/"E1i" pair). Beside a selection whose closed `when` read nothing a refused selection is judged as a lone
    one, and the one body a `when` can refuse over a one-object statement is gated on a key the statement lacks, an
    undecidable body: `not check` fails closed naming the read and the gate fails closed on its condition, in either
    map order (the "GKr2w"/"GKr2rw" pair; the selection the `when` closed on is not applicable, never refused).
    Siblings that every one skip are values the block has, so without the refused value the block is SKIP under `not
    empty` as well and the assertion role fails `not check` closed there, where as a `when` condition FAIL against
    SKIP counts as agreement, since both mean the guard did not hold (alone without `not empty`, the "E1d" row: the
    gated rule is then not applicable); the every-sibling-skips arm of that agreement is reached by no row and stays
    unpinned: over a one-object statement a `when` that closes on the sibling closes on the refused selection's held
    key too, a comparison gate (the "GKk" row) and the unary `Effect !exists` gate alike (the "GKuk" row: the held key
    reads as nothing there, so `!exists` is not applicable rather than true), or refuses its lacking one, so that
    value is not applicable or undecidable and never a decided no
    beside skipping siblings. The block's record is flagged a
    refusal by the block's own read whatever the body decided beside it (the flag says whether the message embeds a
    refusal); beside siblings the refused value leaves a flagged per-value FAIL record under the block in either role;
    where that `not` passes, the block's refused read is written "passed by the negation of a rule that failed", and
    where a `when` condition's block decided it, "was decided by a sibling clause's failure" (the body's no) or "was
    decided by a sibling entry's failure" (a failing sibling past the undecidable value) (pinned by
    `eval_tests.rs:a_blocks_refused_read_over_the_empty_selection_is_judged_with_its_bodys_basis (cases "E1w", "E1d", "E1nk", "E1i", "E1io", "E2", "V1", "SP", "SF", "GS", "GSf", "GSsw", "GSsfd", "GKk", "GKuk", "GKsk", "GKnk", "GKsnk", "GSu", "GSr", "GKr", "GKx", "GKd", "GKr2w", "GKr2rw", "GKek", "GKenk", "SS", "GSs", "D")`
    and `eval_tests.rs:a_gate_role_block_over_a_refused_selection_beside_a_sibling_raises_or_writes_its_own_line_once (cases "GU", "GUd", "GUf", "GD", "MF", "MO")`; the every-entry agreement and disagreement beside a body
    whose no comes from a binding, and the line the two-selection shape writes, are pinned by the first test's
    cases "GSfd", "GSpd", "GKr2d" and "GKr2rd"). A passing sibling decides past the fail-closed `not` as past any
    decided FAIL (`rule main { not check or Maps exists }` passes with one ordinary line). Raising the negation in the
    assertion role instead was considered and not taken: FAIL is the shape every other refusal reaching a strict role
    takes. A `when` or type-block condition raised on a refused read in a strict role fails its block closed as before;
    the condition's raise is then the block's own leaf FAIL, handed up as one, and a type block is every resource at once,
    so a second resource whose body fails on a plain no makes the block's FAIL decided
    (pinned by `eval_tests.rs:a_negated_reference_fails_closed_on_a_refusal_only_fail (cases "R1", "R1b", "R1c", "R3", "T1", "T1b")`);
    the structural rows, the two record shapes and the sites that note no refused read are each a labeled row
    (pinned by `eval_tests.rs:a_negated_reference_decides_by_the_structure_of_the_rules_folds (cases "A1", "A2", "O1", "O2", "S1", "S2", "S3", "M1", "M2", "G1", "N1", "D1", "B1", "B2", "B3", "B4", "L1", "L2", "X1", "X2", "C1", "C2", "U1", "U2", "U3")`).
    The parameterized rows of the same shape read the same (pinned by
    `eval_tests.rs:frame_entries_decide_by_kind_and_a_rule_call_runs_in_its_own_frame (cases "R1", "R3")`).

23. <a name="a-let-bound-numbered-re-read-loses-its-flag"></a> A `let`-bound refusal re-read inside a NUMBERED text
    beside an unregistered marker's reason reads `refusal: false` where the original raise read `true`. A failed
    assignment's error is re-raised on every later read of the name as the same error with its refusal token left
    behind (`Error::repeated`: a later read is a later raise, minted in no predicate run, so it flags no entry); the
    sentence re-read whole is the registered refusal it is, read by text, but the shape `(1) <refusal> (2) <spent
    budget>`, which a raise over a refusal and a budget marker writes, parses to no registered set (the numbered
    parser accepts registered parts only, all or nothing), so the re-read carries no token and names no registered
    text. Recovering the registered parts' tokens through a lenient parse of the numbered text would close it and is
    deferred: the one residual of the token carrier, recorded as the design it keeps. Nothing moves with it but the
    record's flag and the console's remedy line for that re-read; the verdict, the exit code and the registry are the
    same. Pinned as it reads by `eval_tests.rs:a_let_bound_refusal_re_read_keeps_its_flag_by_text_alone`, whose
    residual row goes red when the re-read recovers its token.

24. <a name="a-bare-right-hand-query-reads-the-filtered-map-alone"></a> A key filter's bare right-hand query and a
    function argument in the same place reach the document differently, by design: the bare query, `Props[ keys ==
    Tags[ Key == 'Env' ].Value ]`, reads the map being filtered alone, while a function argument, `Props[ keys ==
    to_upper(Tags[ Key == 'Env' ].Value) ]`, falls back to the resource beside the map when the map does not hold its
    first key (the key filter's right-hand-side rules in `docs/CLAUSES.md`). So over a resource whose `Tags` sits
    beside `Props` rather than inside it, the bare query's `Tags` is a key `Props` lacks, an absence and no refusal: the
    map is answered with the plain marker, a clause over it fails closed as over any map nobody could decide, in the
    gate role and in the assertion role alike, and a
    block that holds that raise beside a sibling's error and is decided past by an `or` sibling owes no refused-read
    line, where the same query over a `Props.Tags` that is a string, or a one-object map under `Tags[*][ Key == 'Env'
    ]`, is refused and owes one. Nothing fails open (the plain marker fails the clause closed), and a `Tags` meant to
    be read from the resource is written with the function spelling or sits inside the filtered map; whether the bare
    query should take the function argument's fallback so the two spellings agree is an open design question, not a
    defect (pinned by
    `eval_tests.rs:a_blocks_pending_refused_selection_is_settled_at_every_exit_in_both_roles (cases "AF", "AFs", "AFr", "AFc", "AFx", "AFy", "AFz", "AFxa", "AFya", "AFza")`).

25. <a name="a-gate-failing-closed-on-a-plain-error-does-not-name-a-refusal-settled-beside-it"></a><a name="a-gate-failing-closed-on-a-plain-error-names-a-refusal-settled-beside-it"></a> A gate that fails
    closed on a plain error names a refusal settled beside it in the same condition after the error, in the
    rule's sentence. Take a `when` condition that calls a rule whose block reads two selections under
    `Resources.*.Tags[*][ Key == 'Env' ]`: one is a one-object map holding an intrinsic beside the compared entry (a
    refused selection), the other either a list or a second one-object selection, and its body raises a converter's
    error (`parse_int` on a word). The rule fails closed on the converter's error, and the run prints the
    condition's sentence ("The rule's condition could not be evaluated, so the rule fails rather than being treated
    as not applicable: ..") naming that error, once per gated rule, followed by "; the condition also met: " and the
    refusal that was pending beside it, bare and at the refused map's path (named nowhere else). The refusal
    did not decide the verdict, so it follows the error and does not replace it. It is named
    once: no refused-read line is written for it, since the sentence is where the walk of the failed condition
    reports every refusal the condition met that the error's text does not carry. The verdict is unchanged. The
    same two selections under `rule check { .. }` (no gate) print both, in either sibling shape: the error's clause
    record and the refusal's sentence at the refused map's path, once each (pinned by
    `tests/validate.rs:a_gate_failing_closed_on_a_plain_error_names_a_refusal_settled_beside_it_in_the_rules_sentence`, whose
    console rows read the path in the output).
    A related difference outside a filter predicate run: a REGISTERED refusal that arrives beside a held
    converter's error replaces the converter's sentence in the raise, while a refusal that is tokened but not
    registered is joined to it (the refusal first, the cause after it, bounded), so the first hides the cause and
    the second keeps it. Both name the refusal; the cause is kept only in the second.

    The first anchor above (`...-plain-error-does-not-name-a-refusal-settled-beside-it`) is the item's old name,
    kept so links written before this item named the refusal still land here.

26. <a name="a-refused-read-line-that-says-no-record-was-held"></a> A refused-read line that says a fold "held no
    record of it" is the evaluator's own error and no finding about the rules file or the input data: nothing in
    either reaches it. The line ends with a sentence that asks for a report to the project's issue tracker with a
    minimal rules file and template that reproduce it, with account ids, ARNs, parameter values and other sensitive
    values removed. It is written for the clause's refused read when an internal check that
    a debug build asserts did not hold: it names the read as the other refused-read lines do and replaces only their
    verdict wording. A release build writes the line and goes on (pinned by
    `eval_tests.rs:the_neutral_word_for_an_unrecorded_entry_is_worded_as_an_internal_error`).

27. <a name="a-binding-read-late-in-a-predicate-run-no-longer-turns-its-entry-plain"></a> A filter predicate whose
    own body raised a refusal, and that reads a file-level `let` for the first time after it, now marks its entry
    refused. The `let` is resolved at that first read and its query raises the same
    sentence again, registered under a newer token; the run reads a token minted while an older scope's binding was
    resolved as no entry's own, so an entry the run's own refusal had marked refused read as plain once the `let`
    was read after it, and the refusal was not reported as one (a plain marker reads as a spent regex budget). The
    verdict of a `some` over a selection that is the LEFT-hand operand of the outer comparison is decided by a
    member that passes, and a refused member is an undecided read that the record and the run's refused-read line
    report (unmeasured on the releases: no release row holds this shape). Where the selection is the RIGHT-hand operand of the outer comparison a clause
    that no resolved right-hand value settles fails closed, so such a clause whose right-hand selection holds
    the refused entry can move from PASS to FAIL with the entry's kind. Whether the `let` was read earlier in
    the file or first inside the run, the entry reads refused.
    The registry keeps the token a run read as its own beside a later registration of the same sentence whose
    token that run does not read as its own: the binding's resolution registering the refusal, and also a comparison
    that meets the memoized refusal's marker later in the run and registers the read, or a wrap of it. All three
    registrations follow that one rule. A comparison held inside a run carries the token it was ranked by to the
    end of the run, so the two variants of the held error (a comparison, and a plain error that a registry lookup
    answers by text) read alike. A refusal that is no run's own, or that a block built inside the run raised, is
    registered as before.

    A filter predicate run that is opened inside the `let`'s own query (the `let` selects with a filter whose
    predicate raises the same sentence) reads the tokens that query mints as its own, and the enclosing run
    does not. One sentence can therefore carry several live tokens at once: the registry lists the newest token
    minted for a sentence and the newest each live run reads as its own (the list is cut at each write, so
    a closed run's token stays until the next write of the sentence), and answers each run with the token it
    owns, the innermost run that owns one first, else the newest. An enclosing run that
    raised the sentence earlier as a plain error, and never held it in a fold, still reads its own token and
    its entry reads refused and the refusal is reported; a `some` over a selection that is the LEFT-hand operand
    of the outer comparison still passes on a sibling that passes, while a selection that is the RIGHT-hand
    operand fails the clause closed when no resolved value in it settles the clause. The nested run reads the token its own raise
    carries, through a marker, a comparison's registration, a wrap or the text read at the end of the run, so
    its entry reads refused and is memoized as refused for every reader of the `let`. A raise that reaches the
    end of the nested run with no token of its own and no registration made inside the run (the run met the
    sentence without raising it afresh) reads the nearest enclosing run's token, which the nested run does not
    own, so that entry reads plain: a refusal minted before the run began, the reading a capture bound
    outside a predicate has. Two root scopes alive on one thread (a shape of the tests alone) share the
    list of live runs the registry reads, as they share the token counter, so a run of the outer
    evaluation keeps its token against writes of the inner one.
