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
Test Case: "MyTest"
PASS Expected Rule = check_rest_api_is_private, Status = SKIP, Got Status = SKIP
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
Test Case: "MyTest1"
PASS Expected Rule = check_rest_api_is_private, Status = SKIP, Got Status = SKIP
Test Case: "MyTest2"
PASS Expected Rule = check_rest_api_is_private, Status = SKIP, Got Status = SKIP
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
Test Case: "MyTest1"
PASS Expected Rule = check_rest_api_is_private, Status = SKIP, Got Status = SKIP
Test Case: "MyTest2"
PASS Expected Rule = check_rest_api_is_private, Status = SKIP, Got Status = SKIP
Test Case: "MyTest3"
PASS Expected Rule = check_rest_api_is_private, Status = FAIL, Got Status = FAIL
Test Case: "MyTest4"
PASS Expected Rule = check_rest_api_is_private, Status = PASS, Got Status = PASS
```

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
Test Case: "MyTest4"
PASS Expected Rule = check_rest_api_is_private, Status = PASS, Got Status = PASS
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
Test Case: "MyTest"
PASS Expected Rule = check_rest_api_is_private, Status = FAIL, Got Status = FAIL
Rule(check_rest_api_is_private, FAIL)
    |  Message: DEFAULT MESSAGE(FAIL)
    Condition(check_rest_api_is_private, PASS)
        |  Message: DEFAULT MESSAGE(PASS)
        Clause(Clause(Location[file:../../../Guard tests/rules.guard, line:3, column:37], Check: %api_gws NOT EMPTY ), PASS)
            |  From: Map((Path("/Resources/apiGw"), MapValue { keys: [String((Path("/Resources/apiGw/Type"), "Type")), String((Path("/Resources/apiGw/Properties"), "Properties"))], values: {"Type": String((Path("/Resources/apiGw/Type"), "AWS::ApiGateway::RestApi")), "Properties": Map((Path("/Resources/apiGw/Properties"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration"), "EndpointConfiguration"))], values: {"EndpointConfiguration": Map((Path("/Resources/apiGw/Properties/EndpointConfiguration"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), "Types"))], values: {"Types": List((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), [String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/0"), "PRIVATE")), String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/1"), "REGIONAL"))]))} }))} }))} }))
            |  Message: DEFAULT MESSAGE(PASS)
    BlockClause(Block[Location[file:../../../Guard tests/rules.guard, line:4, column:3]], FAIL)
        |  Message: DEFAULT MESSAGE(FAIL)
        Conjunction(cfn_guard::rules::exprs::GuardClause, FAIL)
            |  Message: DEFAULT MESSAGE(FAIL)
            Clause(Clause(Location[file:../../../Guard tests/rules.guard, line:5, column:5], Check: Properties.EndpointConfiguration.Types[*]  EQUALS String("PRIVATE")), FAIL)
                |  From: String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/1"), "REGIONAL"))
                |  To: String((Path("../../../Guard tests/rules.guard/5/5/Clause/"), "PRIVATE"))
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
