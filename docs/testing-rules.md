# Testing AWS CloudFormation Guard rules<a name="testing-rules"></a>

You can use the AWS CloudFormation Guard built\-in unit testing framework to verify that your Guard rules work as intended\. This section provides a walkthrough of how to write a unit testing file and how to use it to test your rules file with the `test` command\.

Your unit test file must have one of the following extensions: `.json`, `.JSON`, `.jsn`, `.yaml`, `.YAML`, or `.yml`\.

**Topics**
+ [Prerequisites](#testing-rules-prerequisites)
+ [Overview of Guard unit testing files](#testing-rules-overview)
+ [Walkthrough of writing a Guard rules unit testing file](#testing-rules-example)

## Prerequisites<a name="testing-rules-prerequisites"></a>

Write Guard rules to evaluate your input data against\. For more information, see [Writing Guard rules](writing-rules.md)\.

## Overview of Guard unit testing files<a name="testing-rules-overview"></a>

Guard unit testing files are JSON\- or YAML\-formatted files that contain multiple inputs as well as the expected outcomes for rules written inside a Guard rules file\. There can be multiple samples to assess different expectations\. We recommend that you start by testing for empty inputs and then progressively add information for assessing various rules and clauses\.

Also, we recommend that you name unit testing files using the suffix `_test.json` or `_tests.yaml`\. For example, if you have a rules file named `my_rules.guard`, name your unit testing file `my_rules_tests.yaml`\.

### Syntax<a name="testing-rules-syntax"></a>

The following shows the syntax of a unit testing file in YAML format\.

```
---
- name: <TEST NAME>
  input:
     <SAMPLE INPUT>
   expectations:
     rules:
       <RULE NAME>: [PASS|FAIL|SKIP]
```

### Properties<a name="testing-rules-properties"></a>

Following are the properties of a Guard test file\.

`input`  <a name="testing-rules-properties-input"></a>
Data to test your rules against\. We recommend that your first test uses an empty input, as shown in the following example\.  

```
---
- name: MyTest1
  input {}
```
For subsequent tests, add input data to test\.  
 *Required*: Yes 

`expectations`  <a name="testing-rules-properties-expectations"></a>
The expected outcome when specific rules are evaluated against your input data\. Specify one or multiple rules that you want to test in addition to the expected outcome for each rule\. The expected outcome must be one of the following:  
+ `PASS` – When run against your input data, the rules evaluate to `true`\.
+ `FAIL` – When run against your input data, the rules evaluate to `false`\.
+ `SKIP` – When run against your input data, the rule isn't triggered\.

```
expectations:
    rules:
      check_rest_api_is_private: PASS
```
 *Required*: Yes 

## Walkthrough of writing a Guard rules unit testing file<a name="testing-rules-example"></a>

The following is a rules file named `api_gateway_private.guard`\. The intent for this rule is to check whether all Amazon API Gateway resource types defined in a CloudFormation template are deployed for private access only and have at least one policy statement that allows access from a virtual private cloud \(VPC\)\.

```
#
# Select all AWS::ApiGateway::RestApi resources
#     present in the Resources section of the template. 
#
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi']

#
# Rule intent:         
# 1) All AWS::ApiGateway::RestApi resources deployed must be private.                                            
# 2) All AWS::ApiGateway::RestApi resources deployed must have at least one AWS Identity and Access Management (IAM) policy condition key to allow access from a VPC.
#
# Expectations:        
# 1) SKIP when there are no AWS::ApiGateway::RestApi resources in the template.  
# 2) PASS when:
#     ALL AWS::ApiGateway::RestApi resources in the template have the EndpointConfiguration property set to Type: PRIVATE. 
#     ALL AWS::ApiGateway::RestApi resources in the template have one IAM condition key specified in the Policy property with aws:sourceVpc or :SourceVpc.    
# 3) FAIL otherwise.                                                                                  
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
            # ALL AWS::ApiGateway::RestApi resources in the template have one IAM condition key specified in the Policy property with 
            #     aws:sourceVpc or :SourceVpc
            #           
            some Policy.Statement[*] {
                Condition.*[ keys == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !empty
            }
        }
    }
}
```

This walkthrough tests the first rule intent: All `AWS::ApiGateway::RestApi` resources deployed must be private\.

1. Create a unit testing file called `api_gateway_private_tests.yaml` that contains the following initial test\. With the initial test, add an empty input and expect that the rule `check_rest_api_is_private` will skip because there are no `AWS::ApiGateway::RestApi` resources as inputs\.

   ```
   ---
   - name: MyTest1
     input: {}
     expectations:
       rules:
         check_rest_api_is_private: SKIP
   ```

1. Run the first test in your terminal using the `test` command\. For the `--rules-file` parameter, specify your rules file\. For the `--test-data` parameter, specify your unit testing file\.

   ```
   cfn-guard test \
    --rules-file api_gateway_private.guard \
    --test-data api_gateway_private_tests.yaml \
   ```

   The outcome for the first test is `PASS`\.

   ```
   Test Case #1
   Name: "MyTest1"
     PASS Rules:
       check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP
   ```

1. Add another test to your unit testing file\. Now, extend the testing to include empty resources\. The following is the updated `api_gateway_private_tests.yaml` file\.

   ```
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

1. Run `test` with the updated unit testing file\.

   ```
   cfn-guard test \
    --rules-file api_gateway_private.guard \
    --test-data api_gateway_private_tests.yaml \
   ```

   The outcome for the second test is `PASS`\.

   ```
   Test Case #1
   Name: "MyTest1"
     PASS Rules:
       check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP
   Test Case #2
   Name: "MyTest2"
     PASS Rules:
       check_rest_api_is_private: Expected = SKIP, Evaluated = SKIP
   ```

1. Add two more tests to your unit testing file\. Extend the testing to include the following:
   + An `AWS::ApiGateway::RestApi` resource with no properties specified\.
**Note**  
This isn’t a valid CloudFormation template, but it's useful to test whether the rule works correctly even for malformed inputs\.

     Expect that this test will fail because the `EndpointConfiguration` property isn't specified and is therefore not set to `PRIVATE`\.
   + An `AWS::ApiGateway::RestApi` resource that satisfies the first intent with the `EndpointConfiguration` property set to `PRIVATE` but does not satisfy the second intent because it has no policy statements defined\. Expect that this test will pass\.

   The following is the updated unit testing file\.

   ```
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

1. Run `test` with the updated unit testing file\.

   ```
   cfn-guard test \
    --rules-file api_gateway_private.guard \
    --test-data api_gateway_private_tests.yaml \
   ```

   The third outcome is `FAIL`, and the fourth outcome is `PASS`\.

   ```
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

1. Comment out tests 1–3 in your unit testing file\. Access the verbose context for the fourth test only\. The following is the updated unit testing file\.

   ```
   ---
   #- name: MyTest1
   #  input: {}
   #  expectations:
   #    rules:
   #      check_rest_api_is_private_and_has_access: SKIP
   #- name: MyTest2
   #  input:
   #     Resources: {}
   #  expectations:
   #    rules:
   #      check_rest_api_is_private_and_has_access: SKIP
   #- name: MyTest3
   #  input:
   #    Resources: 
   #      apiGw:
   #        Type: AWS::ApiGateway::RestApi
   #  expectations:
   #    rules:
   #      check_rest_api_is_private_and_has_access: FAIL
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

1. Inspect the evaluation results by running the `test` command in your terminal, using the `--verbose` flag\. Verbose context is useful for understanding evaluations\. In this case, it provides detailed information about why the fourth test succeeded with a `PASS` outcome\.

   ```
   cfn-guard test \
     --rules-file api_gateway_private.guard \
     --test-data api_gateway_private_tests.yaml \
     --verbose
   ```

   Here is the output from that run\.

   ```
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

   The key observation from the output is the line `Clause(Location[file:api_gateway_private.guard, line:22, column:5], Check: Properties.EndpointConfiguration.Types[*] EQUALS String("PRIVATE")), PASS)`, which states that the check passed\. The example also showed the case where `Types` was expected to be an array, but a single value was given\. In that case, Guard continued to evaluate and provided a correct result\.

1. Add a test case like the fourth test case to your unit testing file for an `AWS::ApiGateway::RestApi` resource with the `EndpointConfiguration` property specified\. The test case will fail instead of pass\. The following is the updated unit testing file\.

   ```
   ---
   #- name: MyTest1
   #  input: {}
   #  expectations:
   #    rules:
   #      check_rest_api_is_private_and_has_access: SKIP
   #- name: MyTest2
   #  input:
   #     Resources: {}
   #  expectations:
   #    rules:
   #      check_rest_api_is_private_and_has_access: SKIP
   #- name: MyTest3
   #  input:
   #    Resources: 
   #      apiGw:
   #        Type: AWS::ApiGateway::RestApi
   #  expectations:
   #    rules:
   #      check_rest_api_is_private_and_has_access: FAIL
   #- name: MyTest4
   #  input:
   #    Resources: 
   #      apiGw:
   #        Type: AWS::ApiGateway::RestApi
   #        Properties:
   #          EndpointConfiguration:
   #            Types: "PRIVATE"
   #  expectations:
   #    rules:
   #      check_rest_api_is_private: PASS
   - name: MyTest5
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

1. Run the `test` command with the updated unit testing file using the `--verbose` flag\.

   ```
   cfn-guard test \
    --rules-file api_gateway_private.guard \
    --test-data api_gateway_private_tests.yaml \
    --verbose
   ```

   The outcome is `FAIL` as expected because `REGIONAL` is specified for `EndpointConfiguration` but is not expected\.

   ```
   Test Case #1
   Name: "MyTest5"
     PASS Rules: 
       check_rest_api_is_private: Expected = FAIL, Evaluated = FAIL
   Rule(check_rest_api_is_private, FAIL)
       |  Message: DEFAULT MESSAGE(FAIL)
       Condition(check_rest_api_is_private, PASS) 
           |  Message: DEFAULT MESSAGE(PASS)
           Clause(Clause(Location[file:api_gateway_private.guard, line:20, column:37], Check: %api_gws NOT EMPTY ), PASS)
               |  From: Map((Path("/Resources/apiGw"), MapValue { keys: [String((Path("/Resources/apiGw/Type"), "Type")), String((Path("/Resources/apiGw/Properties"), "Properties"))], values: {"Type": String((Path("/Resources/apiGw/Type"), "AWS::ApiGateway::RestApi")), "Properties": Map((Path("/Resources/apiGw/Properties"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration"), "EndpointConfiguration"))], values: {"EndpointConfiguration": Map((Path("/Resources/apiGw/Properties/EndpointConfiguration"), MapValue { keys: [String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), "Types"))], values: {"Types": List((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types"), [String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/0"), "PRIVATE")), String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/1"), "REGIONAL"))]))} }))} }))} }))
               |  Message: DEFAULT MESSAGE(PASS)
       BlockClause(Block[Location[file:api_gateway_private.guard, line:21, column:3]], FAIL)
           |  Message: DEFAULT MESSAGE(FAIL)
           Conjunction(cfn_guard::rules::exprs::GuardClause, FAIL)
               |  Message: DEFAULT MESSAGE(FAIL)
               Clause(Clause(Location[file:api_gateway_private.guard, line:22, column:5], Check: Properties.EndpointConfiguration.Types[*]  EQUALS String("PRIVATE")), FAIL)
                   |  From: String((Path("/Resources/apiGw/Properties/EndpointConfiguration/Types/1"), "REGIONAL"))
                   |  To: String((Path("api_gateway_private.guard/22/5/Clause/"), "PRIVATE"))
                   |  Message: (DEFAULT: NO_MESSAGE)
   ```

   The verbose output of the `test` command follows the structure of the rules file\. Every block in the rules file is a block in the verbose output\. The top\-most block is each rule\. If there are `when` conditions against the rule, they appear in a sibling condition block\. In the following example, the condition `%api_gws !empty` is tested and it passes\.

   ```
   rule check_rest_api_is_private when %api_gws !empty {
   ```

   Once the condition passes, we test the rule clauses\.

   ```
   %api_gws {
       Properties.EndpointConfiguration.Types[*] == "PRIVATE"                      
   }
   ```

   `%api_gws` is a block rule that corresponds to the `BlockClause` level in the output \(line:21\)\. The rule clauseis a set of conjunction \(AND\) clauses, where each conjunction clause is a set of disjunctions \(`OR`s\)\. The conjunction has a single clause, `Properties.EndpointConfiguration.Types[*] == "PRIVATE"`\. Therefore, the verbose output shows a single clause\. The path `/Resources/apiGw/Properties/EndpointConfiguration/Types/1` shows which values in the input are compared, which in this case is the element for `Types` indexed at 1\.

In [Validating input data against Guard rules](validating-rules.md), you can use the examples in this section to use the `validate` command to evaluate input data against rules\.