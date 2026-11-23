# Guard: Unit Testing

## Recommended Readings

[Guard: Clauses](CLAUSES.md)
[Guard: Query and Filtering](QUERY_AND_FILTERING.md)
[Guard: Context-Aware Evaluations, this and Loops](CONTEXTAWARE_EVALUATIONS_AND_LOOPS.md)

It is essential for rule authors to gain confidence that policies defined in a Guard file do indeed comply with expectations. With the Guard 2.0 tool you can leverage the built-in unit testing support that helps validate Guard policy files. 

## Anatomy of a Unit Testing File 

All unit testing files are YAML/JSON formatted files. Each test file can contain multiple inputs along with the expected outcomes for rules written inside a Guard file. The anatomy of a unit testing file is as shown below (YAML format shown):

```yaml
---
- name: <TEST NAME>
  input:
    <SAMPLE INPUT>
  expectations:
    rules:
      <RULE NAME>: [PASS|FAIL|SKIP]

```

There can be multiple samples to assess different expectations. It is recommended to start with testing for empty inputs and then progressively add information for assessing various rules and clauses that you are attempting to assess. 

A test file is read with the same loader that `validate` reads a data file with, so an `input:` means exactly what the same text means as a template. That has a few consequences for the file itself:

* YAML anchors and aliases (`&base` / `*base`, including `<<: *base`) are resolved in a test file, within two bounds. An aliased `input:` is a copy of the anchored one, and a finding inside it is reported at the anchored node's position, which is where the value is written. The copies are counted, in nodes and in bytes, per test case: a case that would copy more than 1,000,000 nodes, or more than 64 MiB of scalar text and key names, through anchors and aliases fails, naming the alias that crossed the budget, the budget it crossed and the case as what the budget is spent over, and the other cases keep their verdicts. Recording an anchor is not charged, since an anchor nothing aliases is not a copy of anything, and each alias is charged to the case that uses it, so a template anchored in one case and aliased by every other case costs each of them one copy, however many cases there are. What the file's anchors hold together is bounded on its own, over the whole file: at most the budget plus the file's size, in nodes and in bytes, because every anchored node is kept whole for the aliases that may follow it and an anchor nested inside another is kept once on its own and once inside each anchor around it; an anchor that would take that past the bound fails the case holding it and every case that aliases it, naming the anchor. A mapping key's bytes count once for the key and once more for every node under it, which is how many times the evaluated document carries the name in its paths. A chain of anchors that each alias the one before them ten times reaches the node budget in six levels inside one case, and a 64 KiB scalar reaches the byte budget after about a thousand aliases in one case; anchor the shared input once and alias it directly. The second bound covers the whole file and no case resets it: 1,000 copied nodes for every YAML event in the file other than an alias (a scalar, or the start or end of a sequence or mapping, so the count does not change with how the file is laid out, and an alias does not raise the bound it is held to) and 100 copied bytes for every byte of the file, never fewer than one case's budget. The events are counted over the whole file before anything is copied, so the bound is the same for every alias wherever it sits and does not change with the order of the cases; a file of a few hundred such events copies at most 1,000,000 nodes in all however many cases it has, and the error names this ceiling and says that it does not reset. The ceiling bounds the copies relative to the file's own size; the whole file, with every copy, is read into memory before any case runs. An alias to a name that no earlier node anchors fails its case too. A data file given to `validate` resolves aliases the same way, with one budget for the whole document rather than one per case, so an `input:` that uses one is a template you can hand to `validate` as is.
* A case the command cannot read fails only that case, with the reason as that case's error, and the other cases in the file keep their verdicts. Inside `input:` that is a node the loader refused: a key that is null, a sequence, or an alias the loader refused, a merge key (`<<`) given anything but a mapping or a sequence of mappings, an alias to a name no earlier node anchors, a copy that would cross a bound above, or a sequence or mapping tagged with an intrinsic's name under `!!` (`!!If [IsProd, a, b]`, a typo of `!If`); `validate` refuses a data file holding the same bytes. In the case's other fields it is anything the command cannot read as that field: a `name` that is not a scalar, `expectations` or the `rules` under them that are not a mapping, a rule's expected status that is not a scalar, a missing `input` or `expectations`, a field written twice, a rule expected twice, or a node the loader refused standing in any of those places. The error names the field and carries the loader's reason where there is one. The whole file is refused, with no case reported, in exactly these situations: the document itself is unreadable (nesting deeper than 128 levels, whether written inline or reached through an alias, or a second document after the first); the document is not a sequence of cases; or a case is not a mapping, including an alias the loader refused standing for a case, a case mapping tagged with an intrinsic's name under `!!`, and a key the loader cannot read beside a case's fields, which makes the case mapping itself unreadable.
* A file that holds no document (empty, or only comments, or only `---`) has no test cases and is not an error. `rules:` with nothing after it is an empty set of expectations.
* A field written twice in one case (`name`, `input` or `expectations`) fails that case with an error that names both positions; the usual cause is a second case pasted without its leading `- `. A rule named twice under `rules:` fails the case too, since a rule has one expectation per case. A key written twice inside `input:` keeps the last value and prints the same warning `validate` prints for a template.
* A case `name` that is not a string keeps its spelling: `1.50` is reported as `1.50`, `1e3` as `1e3`, `0x1F` as `0x1F` and `True` as `True`. Two cases in one file with the same name both run. When one of them repeats the other's `input:`, the shape of a pasted case, the command warns on stderr naming both positions, because reports and JUnit ids tell cases apart by name; `1.5` and `"1.5"` are the same name. A name repeated over cases with different inputs groups them under one label and draws no warning, whether or not their expectations agree: a suite with one rule has three verdicts to choose from, so cases agreeing on them is ordinary, and published suites do it throughout.
* In a JSON test file, a character outside the Basic Multilingual Plane that is written as a surrogate-pair escape (the way `json.dumps` writes \ud83d\ude00 by default) is read as that character, and a raw U+0085, U+2028 or U+2029 inside a string is read as that character too, where the YAML reader on its own would fold it as a line break. Positions in a verbose report are those of the source text, numbered as the YAML reader numbers lines: those three characters each end a line, so text after one of them on the same physical line is reported on the next line. Three more shapes of valid JSON that the YAML reader's scanner does not accept are rewritten before it reads the text, so the file reads as written: a member name that spans more than 1024 bytes from its opening quote to its colon is read as an explicit key, a line break between a member name and its colon as a space, and a raw U+007F-U+009F character (other than U+0085) or U+FFFE or U+FFFF inside a string as that character. A lone surrogate escape, which is not a character, is still refused with a message saying the file is valid JSON and naming it.
* For code that uses cfn-guard as a library: `TestSpec`, the parsed case (`cfn_guard::commands::test::TestSpec`), is built by the command from the spec file and no longer derives `Serialize` or `Deserialize`. Its `input` is the loader's own value rather than a serde value, and it cannot be named or constructed outside the crate.

Let’s illustrate this with an example.

## Example Rule

Here is the intent for the rule: 

1. Check that all [Amazon API Gateway resource types](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-apigateway-restapi.html) defined inside a CloudFormation template 
  * are deployed for only private access. 
  * and at least one policy statement that allows access from some VPC. 

```
#
# Select from Resources section of the template all ApiGateway resources 
# present in the template. 
#
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi']

#
# Rule intent         
# a) All ApiGateway instances deployed must be private                                             
# b) All ApiGateway instances must have atleast one IAM policy condition key to allow access m a VPC
#
# Expectations:        
# 1) SKIP when there are not API Gateway instances in the plate    
# 2) PASS when ALL ApiGateway instances MUST be "PRIVATE"         
#              ALL ApiGateway instances MUST have one IAM Condition key with aws:sourceVpc or :SourceVpc       
# 3) FAIL otherwise                                                                                   
#
#

rule check_rest_api_is_private when %api_gws !empty           
    %api_gws {
        Properties.EndpointConfiguration.Types[*] == "PRIVATE"                             
    }  
}       

rule check_rest_api_has_vpc_access when check_rest_api_is_private {
    %api_gws {
        Properties {
            #
            # ALL ApiGateways must have atleast one IAM statement that has Condition keys with 
            #     aws:sourceVpc
            #           
            some Policy.Statement[*] {
                Condition.*[ keys == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !empty
            }
        }
    }
}
```

The rule is shown above. How do you test that the rules do work as intended?

### Testing the rule(s)

First you don’t write complex rules. They get harder to maintain and test. The recommendation is you write smaller rules that you combine to specify larger rules. You will start with intent (1). 

```
#
# Select from Resources section of the template all ApiGateway resources 
# present in the template. 
#
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]                             

#
# Rule intent                                                                                 
# a) All ApiGateway instances deployed must be private                                           
# b) All ApiGateway instances must have atleast one IAM policy condition key to allow accessm a VPC           
#
# Expectations:                                                                            
# 1) SKIP when there are not API Gateway instances in the template                              
# 2) PASS when ALL ApiGateway instances MUST be "PRIVATE" and ALL ApiGateway 
  instances MUST have one IAM Condition key with aws:sourceVpc or aws:SourceVpc       
# 3) FAIL otherwise                   
#
#

rule check_rest_api_is_private when %api_gws !empty {                                       
  %api_gws {
    Properties.EndpointConfiguration.Types[*] == "PRIVATE"                                    
  }   
}    
```

First, you should test expectations starting from empty input and progressively add properties needed to test. Start a file with the suffix `_tests.yaml`. If the name of the Guard policy file is  `api_gateway_private.guard` then you should name the testing file `api_gateway_private_tests.yaml`. Here is the first test:

```yaml
---
- name: MyTest  
  input: {}
  expectations:
    rules:
      check_rest_api_is_private: SKIP
```

You `expect` that `rule` `check_rest_api_is_private` to skip. You can now run the test using: 

```bash
cfn-guard test                                 \
  --rules-file api_gateway_private.guard       \
  --test-data api_gateway_private_tests.yaml
```

The output you see is `PASS` for the test. 

```bash
Test Case #1
Name: "MyTest"
  PASS Rules:
    check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP
```

Now let us extend the testing to include empty resources:

```yaml
---
- name: MyTest1
  input: {}
  expectations:
    rules:
      check_rest_api_is_private: SKIP
- name: MyTest2
  input:
     Resources: {}
  expectations:
    rules:
      check_rest_api_is_private: SKIP
```

Now you can re-run the test and should see:

```bash
Test Case #1
Name: "MyTest1"
  PASS Rules:
    check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP

Test Case #2
Name: "MyTest2"
  PASS Rules:
    check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP
```

You can now add an Amazon API Gateway resource type that was missing `Properties` (This isn’t a valid CFN template, but nonetheless testing that the rule works correctly even for these malformed inputs is useful.), and one that satisfies only `EndpointConfiguration` attribute and has no policy statements defined. You should expect this to `FAIL`. Here is the testing you should have: 

```yaml
---
- name: MyTest1
  input: {}
  expectations:
    rules:
      check_rest_api_is_private: SKIP
- name: MyTest2
  input:
     Resources: {}
  expectations:
    rules:
      check_rest_api_is_private: SKIP
- name: MyTest3
  input:
    Resources: 
      apiGw:
        Type: AWS::ApiGateway::RestApi
  expectations:
    rules:
      check_rest_api_is_private: FAIL
- name: MyTest4
  input:
    Resources: 
      apiGw:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types: "PRIVATE"
  expectations:
    rules:
      check_rest_api_is_private: PASS
```

and a sample run you should see:

```bash
Test Case #1
Name: "MyTest1"
  PASS Rules:
    check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP

Test Case #2
Name: "MyTest2"
  PASS Rules:
    check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP

Test Case #3
Name: "MyTest3"
  PASS Rules:
    check_rest_api_is_private: Expected = FAIL, Evaluated = FAIL

Test Case #4
Name: "MyTest4"
  PASS Rules:
    check_rest_api_is_private: Expected = PASS, Evaluated = PASS
```

A rule whose `when` condition fails closed on a refusal (a read the evaluator refused, an intrinsic function beside the compared value for instance) is evaluated `FAIL`, and its line says why whatever the expectation on it: the default output ends the line with `, Reason = <the rule's sentence>`, on a met `Expected = FAIL` line as on an unmet one, the `json` and `yaml` outputs carry the sentence under `reason` on that rule's entry in `passed_rules` or `failed_rules`, and the `junit` output writes it as the passed case's `<system-out>` element or in the failed case's failure text.

### How do I know that `EndpointConfiguration` check did indeed succeed for PASS case?

When testing you can specify the `--verbose` flag that lets you inspect evaluation results. [Before you ask, yes we plan to expose clause success failure summary like validate, but currently we have verbose as the option]. Often verbose context is needed to understand the evaluations. For this run, let us test only the last input, so you should comment out the earlier tests for this run (or create a file with this single input). Here is how it would look:

```yaml
---
---
#- name: "MyTest1"
#  input: {}
#  expectations:
#    rules:
#      check_rest_api_is_private: SKIP
#- name: "MyTest2"
#  input:
#    Resources: {}
#  expectations:
#    rules:
#      check_rest_api_is_private: SKIP
#- name: "MyTest3"
#  input:
#    Resources:
#      apiGw:
#        Type: AWS::ApiGateway::RestApi
#  expectations:
#    rules:
#      check_rest_api_is_private: FAIL
- name: "MyTest4"
  input:
    Resources:
      apiGw:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types: "PRIVATE"
  expectations:
    rules:
      check_rest_api_is_private: PASS
```

Now you re-run the test but with the verbose flag on:

```bash
cfn-guard test                                 \
  --rules-file api_gateway_private.guard       \
  --test-data api_gateway_private_tests.yaml   \
  --verbose
```

Here is the output from that run:

```bash
Test Case #1
Name: "MyTest4"
  PASS Rules:
    check_rest_api_is_private: Expected = PASS, Evaluated = PASS
Rule(check_rest_api_is_private, PASS)
    |  Message: DEFAULT MESSAGE(PASS)
    Condition(check_rest_api_is_private, PASS)
        |  Message: DEFAULT MESSAGE(PASS)
        Clause(Clause(Location[file:api_gateway_private.guard, line:20, column:37], Check: %api_gws NOT EMPTY ), PASS)
            |  From: Map((Path("/Resources/apiGw"), MapValue { keys: [String((Path("/Resources/apiGw/Type"), "Type")), String((Path("/Resources/apiGw/Properties"), "Properties"))], values: {"Type": String((Path("/Resources/apiGw/Type"), "AWS::ApiGateway::RestApi")), "Properties": Map((Path("/Resources/apiGw/Properties"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration"), "EndpointConfiguration"))], values: {"EndpointConfiguration": Map((Path("/Resources/apiGw/Properties/EndpointConfiguration"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), "Types"))], values: {"Types": String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), "PRIVATE"))} }))} }))} }))
            |  Message: (DEFAULT: NO_MESSAGE)
    Conjunction(cfn_guard::rules::exprs::GuardClause, PASS)
        |  Message: DEFAULT MESSAGE(PASS)
        Clause(Clause(Location[file:api_gateway_private.guard, line:22, column:5], Check: Properties.EndpointConfiguration.Types[*]  EQUALS String("PRIVATE")), PASS)
            |  Message: (DEFAULT: NO_MESSAGE)
```

This is bit dense, but the key observation is the line that says `Clause(Location[file:api_gateway_private.guard, line:22, column:5], Check: Properties.EndpointConfiguration.Types[*]  EQUALS String("PRIVATE")), PASS) `

that states that the check did PASS. The example also showed the case where `Types` was expected to be an array, but a single value was given. Guard will still evaluate and still provide a correct result. Now you should add a test case for `FAIL`ure.  You can add this to the end of the test file.

```yaml
- name: "MyTest"
  input:
    Resources: 
      apiGw:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types: [PRIVATE, REGIONAL]
  expectations:
    rules:
      check_rest_api_is_private: FAIL
```

Now let us run the `test` command again:

```bash
Test Case #1
Name: "MyTest"
  PASS Rules:
    check_rest_api_is_private: Expected = FAIL, Evaluated = FAIL
Rule(check_rest_api_is_private, FAIL)
    |  Message: DEFAULT MESSAGE(FAIL)
    Condition(check_rest_api_is_private, PASS)
        |  Message: DEFAULT MESSAGE(PASS)
        Clause(Clause(Location[file:api_gateway_private.guard, line:3, column:37], Check: %api_gws NOT EMPTY ), PASS)
            |  From: Map((Path("/Resources/apiGw"), MapValue { keys: [String((Path("/Resources/apiGw/Type"), "Type")), String((Path("/Resources/apiGw/Properties"), "Properties"))], values: {"Type": String((Path("/Resources/apiGw/Type"), "AWS::ApiGateway::RestApi")), "Properties": Map((Path("/Resources/apiGw/Properties"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration"), "EndpointConfiguration"))], values: {"EndpointConfiguration": Map((Path("/Resources/apiGw/Properties/EndpointConfiguration"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), "Types"))], values: {"Types": List((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), [String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/0"), "PRIVATE")), String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/1"), "REGIONAL"))]))} }))} }))} }))
            |  Message: DEFAULT MESSAGE(PASS)
    BlockClause(Block[Location[file:api_gateway_private.guard, line:4, column:3]], FAIL)
        |  Message: DEFAULT MESSAGE(FAIL)
        Conjunction(cfn_guard::rules::exprs::GuardClause, FAIL)
            |  Message: DEFAULT MESSAGE(FAIL)
            Clause(Clause(Location[file:api_gateway_private.guard, line:5, column:5], Check: Properties.EndpointConfiguration.Types[*]  EQUALS String("PRIVATE")), FAIL)
                |  From: String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/1"), "REGIONAL"))
                |  To: String((Path("api_gateway_private.guard/5/5/Clause/"), "PRIVATE"))
                |  Message: (DEFAULT: NO_MESSAGE)

```

The check fails as `REGIONAL` was not expected. 

### Understanding the verbose output when testing

The verbose output mostly follows the structure inside the Guard policy file. Every block in the Guard policy file is a block in the verbose output. The top-most is each rule. If there are `when` conditions against the rule then they would appear as a sibling `Condition` block. In this example the condition `%api_gws !empty` is being tested and it `PASS`es. 

```
rule check_rest_api_is_private when %api_gws !empty {    
```

Once the condition passes, we drop into the rule clauses. 

```
%api_gws {
    Properties.EndpointConfiguration.Types[*] == "PRIVATE"                      
}   
```

`%api_gws` is a block Guard rule that corresponds to `BlockClause` level in the output (`line: 21`). The next is a set of conjunction (AND) clauses, where each conjunction clause is a set of disjunctions (ORs). The` Conjunction` has a single clause, `Properties.EndpointConfiguration.Types[*] == "PRIVATE"`, the output therefore shows a single `Clause`. The path `/Resources/apiGw/Properties/EndpointConfiguration/Types/1` shows which values in the input are getting compared, in this case the element for `Types` indexed at `1`.
