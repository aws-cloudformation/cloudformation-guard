# Assigning and referencing variables in AWS CloudFormation Guard rules<a name="variables"></a>

You can assign variables in your AWS CloudFormation Guard rules files to store information that you want to reference in your Guard rules\. Guard supports one\-shot variable assignment\. Variables are evaluated lazily, meaning that Guard only evaluates variables when rules are run\.

**Topics**
+ [Assigning variables](#assigning-variables)
+ [Referencing variables](#referencing-variables)
+ [Variable scope](#variable-scope)
+ [Examples of variables in Guard rules files](#variables-examples)

## Assigning variables<a name="assigning-variables"></a>

Use the `let` keyword to initialize and assign a variable\. As a best practice, use snake case for variable names\. Variables can store static literals or dynamic properties resulting from queries\. In the following example, the variable `ecs_task_definition_task_role_arn` stores the static string value `arn:aws:iam:123456789012:role/my-role-name`\.

```
let ecs_task_definition_task_role_arn = 'arn:aws:iam::123456789012:role/my-role-name'
```

In the following example, the variable `ecs_tasks` stores the results of a query that searches for all `AWS::ECS::TaskDefinition` resources in an AWS CloudFormation template\. You could reference `ecs_tasks` to access information about those resources when you write rules\.

```
let ecs_tasks = Resources.*[
    Type == 'AWS::ECS::TaskDefinition'
]
```

## Referencing variables<a name="referencing-variables"></a>

Use the `%` prefix to reference a variable\.

Based on the `ecs_task_definition_task_role_arn` variable example in [Assigning variables](#assigning-variables), you can reference `ecs_task_definition_task_role_arn` in the `query|value literal` section of a Guard rule clause\. Using that reference ensures that the value specified for the `TaskDefinitionArn` property of any `AWS::ECS::TaskDefinition` resources in a CloudFormation template is the static string value `arn:aws:iam:123456789012:role/my-role-name`\.

```
Resources.*.Properties.TaskDefinitionArn == %ecs_task_definition_role_arn
```

Based on the `ecs_tasks` variable example in [Assigning variables](#assigning-variables), you can reference `ecs_tasks` in a query \(for example, %ecs\_tasks\.Properties\)\. First, Guard evaluates the variable `ecs_tasks` and then uses the returned values to traverse the hierarchy\. If the variable `ecs_tasks` resolves to non\-string values, then Guard throws an error\.

**Note**  
Currently, Guard doesn't support referencing variables inside custom error messages\.

## Variable scope<a name="variable-scope"></a>

Scope refers to the visibility of variables defined in a rules file\. A variable name can only be used once within a scope\. There are three levels where a variable can be declared, or three possible variable scopes:
+ **File\-level** – Usually declared at the top of the rules file, you can use file\-level variables in all rules within the rules file\. They are visible to the entire file\.

  In the following example rules file, the variables `ecs_task_definition_task_role_arn` and `ecs_task_definition_execution_role_arn` are initialized at the file\-level\.

  ```
  let ecs_task_definition_task_role_arn = 'arn:aws:iam::123456789012:role/my-task-role-name'
  let ecs_task_definition_execution_role_arn = 'arn:aws:iam::123456789012:role/my-execution-role-name'
  
  rule check_ecs_task_definition_task_role_arn
  {
      Resources.*.Properties.TaskRoleArn == %ecs_task_definition_task_role_arn
  }
  
  rule check_ecs_task_definition_execution_role_arn
  {
      Resources.*.Properties.ExecutionRoleArn == %ecs_task_definition_execution_role_arn
  }
  ```
+ **Rule\-level** – Declared within a rule, rule\-level variables are only visible to that specific rule\. Any references outside of the rule result in an error\.

  In the following example rules file, the variables `ecs_task_definition_task_role_arn` and `ecs_task_definition_execution_role_arn` are initialized at the rule\-level\. The `ecs_task_definition_task_role_arn` can only be referenced within the `check_ecs_task_definition_task_role_arn` named rule\. You can only reference the `ecs_task_definition_execution_role_arn` variable within the `check_ecs_task_definition_execution_role_arn` named rule\.

  ```
  rule check_ecs_task_definition_task_role_arn
  {
      let ecs_task_definition_task_role_arn = 'arn:aws:iam::123456789012:role/my-task-role-name'
      Resources.*.Properties.TaskRoleArn == %ecs_task_definition_task_role_arn
  }
  
  rule check_ecs_task_definition_execution_role_arn
  {
      let ecs_task_definition_execution_role_arn = 'arn:aws:iam::123456789012:role/my-execution-role-name'
      Resources.*.Properties.ExecutionRoleArn == %ecs_task_definition_execution_role_arn
  }
  ```
+ **Block\-level** – Declared within a block, such as a `when` clause, block\-level variables are only visible to that specific block\. Any references outside of the block result in an error\.

  In the following example rules file, the variables `ecs_task_definition_task_role_arn` and `ecs_task_definition_execution_role_arn` are initialized at the block\-level within the `AWS::ECS::TaskDefinition` type block\. You can only reference the `ecs_task_definition_task_role_arn` and `ecs_task_definition_execution_role_arn` variables within the `AWS::ECS::TaskDefinition` type blocks for their respective rules\.

  ```
  rule check_ecs_task_definition_task_role_arn
  {
      AWS::ECS::TaskDefinition
      {
          let ecs_task_definition_task_role_arn = 'arn:aws:iam::123456789012:role/my-task-role-name'
          Properties.TaskRoleArn == %ecs_task_definition_task_role_arn
      }
  }
  
  rule check_ecs_task_definition_execution_role_arn
  {
      AWS::ECS::TaskDefinition
      {
          let ecs_task_definition_execution_role_arn = 'arn:aws:iam::123456789012:role/my-execution-role-name'
          Properties.ExecutionRoleArn == %ecs_task_definition_execution_role_arn
      }
  }
  ```

## Examples of variables in Guard rules files<a name="variables-examples"></a>

The following sections provide examples of both static and dynamic assignment of variables\.

### Static assignment<a name="assigning-static-variables"></a>

The following is an example CloudFormation template\.

```
Resources:
  EcsTask:
    Type: 'AWS::ECS::TaskDefinition'
    Properties:
      TaskRoleArn: 'arn:aws:iam::123456789012:role/my-role-name'
```

Based on this template, you can write a rule called `check_ecs_task_definition_task_role_arn` that ensures that the `TaskRoleArn` property of all `AWS::ECS::TaskDefinition` template resources is `arn:aws:iam::123456789012:role/my-role-name`\.

```
rule check_ecs_task_definition_task_role_arn
{
    let ecs_task_definition_task_role_arn = 'arn:aws:iam::123456789012:role/my-role-name'
    Resources.*.Properties.TaskRoleArn == %ecs_task_definition_task_role_arn
}
```

Within the scope of the rule, you can initialize a variable called `ecs_task_definition_task_role_arn` and assign to it the static string value `'arn:aws:iam::123456789012:role/my-role-name'`\. The rule clause checks whether the value specified for the `TaskRoleArn` property of the `EcsTask` resource is `arn:aws:iam::123456789012:role/my-role-name` by referencing the `ecs_task_definition_task_role_arn` variable in the `query|value literal` section\.

### Dynamic assignment<a name="example-dynamic-assignment"></a>

The following is an example CloudFormation template\.

```
Resources:
  EcsTask:
    Type: 'AWS::ECS::TaskDefinition'
    Properties:
      TaskRoleArn: 'arn:aws:iam::123456789012:role/my-role-name'
```

Based on this template, you can initialize a variable called `ecs_tasks` within the scope of the file and assign to it the query `Resources.*[ Type == 'AWS::ECS::TaskDefinition'`\. Guard queries all resources in the input template and stores information about them in `ecs_tasks`\. You can also write a rule called `check_ecs_task_definition_task_role_arn` that ensures that the `TaskRoleArn` property of all `AWS::ECS::TaskDefinition` template resources is `arn:aws:iam::123456789012:role/my-role-name`

```
let ecs_tasks = Resources.*[
    Type == 'AWS::ECS::TaskDefinition'
]

rule check_ecs_task_definition_task_role_arn
{
    %ecs_tasks.Properties.TaskRoleArn == 'arn:aws:iam::123456789012:role/my-role-name'
}
```

The rule clause checks whether the value specified for the `TaskRoleArn` property of the `EcsTask` resource is `arn:aws:iam::123456789012:role/my-role-name` by referencing the `ecs_task_definition_task_role_arn` variable in the `query` section\.

### Enforcing AWS CloudFormation template configuration<a name="example-3"></a>

Let’s walk through a more complex example of a production use case\. In this example, we write Guard rules to ensure stricter controls on how Amazon ECS tasks are defined\.

The following is an example CloudFormation template\.

```
Resources:
  EcsTask:
    Type: 'AWS::ECS::TaskDefinition'
    Properties:
      TaskRoleArn: 
        'Fn::GetAtt': [TaskIamRole, Arn]
      ExecutionRoleArn:
        'Fn::GetAtt': [ExecutionIamRole, Arn]

  TaskIamRole:
    Type: 'AWS::IAM::Role'
    Properties:
      PermissionsBoundary: 'arn:aws:iam::123456789012:policy/MyExamplePolicy'

  ExecutionIamRole:
    Type: 'AWS::IAM::Role'
    Properties:
      PermissionsBoundary: 'arn:aws:iam::123456789012:policy/MyExamplePolicy'
```

Based on this template, we write the following rules to ensure that these requirements are met:
+ Each `AWS::ECS::TaskDefinition` resource in the template has both a task role and an execution role attached\.
+ The task roles and execution roles are AWS Identity and Access Management \(IAM\) roles\.
+ The roles are defined in the template\.
+ The `PermissionsBoundary` property is specified for each role\.

```
# Select all Amazon ECS task definition resources from the template
let ecs_tasks = Resources.*[
    Type == 'AWS::ECS::TaskDefinition'
]

# Select a subset of task definitions whose specified value for the TaskRoleArn property is an Fn::Gett-retrievable attribute
let task_role_refs = some %ecs_tasks.Properties.TaskRoleArn.'Fn::GetAtt'[0]

# Select a subset of TaskDefinitions whose specified value for the ExecutionRoleArn property is an Fn::Gett-retrievable attribute
let execution_role_refs = some %ecs_tasks.Properties.ExecutionRoleArn.'Fn::GetAtt'[0]

# Verify requirement #1
rule all_ecs_tasks_must_have_task_end_execution_roles 
    when %ecs_tasks !empty 
{
    %ecs_tasks.Properties {
        TaskRoleArn exists
        ExecutionRoleArn exists
    }
}

# Verify requirements #2 and #3
rule all_roles_are_local_and_type_IAM
    when all_ecs_tasks_must_have_task_end_execution_roles
{
    let task_iam_references = Resources.%task_role_refs
    let execution_iam_reference = Resources.%execution_role_refs

    when %task_iam_references !empty {
        %task_iam_references.Type == 'AWS::IAM::Role'
    }

    when %execution_iam_reference !empty {
        %execution_iam_reference.Type == 'AWS::IAM::Role'
    }
}

# Verify requirement #4
rule check_role_have_permissions_boundary
    when all_ecs_tasks_must_have_task_end_execution_roles
{
    let task_iam_references = Resources.%task_role_refs
    let execution_iam_reference = Resources.%execution_role_refs

    when %task_iam_references !empty {
        %task_iam_references.Properties.PermissionsBoundary exists
    }

    when %execution_iam_reference !empty {
        %execution_iam_reference.Properties.PermissionsBoundary exists
    }
}
```