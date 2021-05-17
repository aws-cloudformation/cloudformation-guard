# Guard: Query, Projection and Interpolation

## Recommended Readings

[AWS CloudFormation Guard](../README.md) 
[Guard: Clauses](CLAUSES.md)
[Guard: Query and Filtering](QUERY_AND_FILTERING.md)

## What are variables?

Variables in Guard are used to store information that needs to be referenced in an easy and repeatable fashion while authoring simple and complex rules. Variables are defined by keeping the concept of “immutability” in mind and therefore allow only a single shot assignment. Variables are evaluated lazily, meaning that the Guard engine only evaluates variables when it encounters such during the rule execution. Variables can store both static literals and dynamic properties resulting from Guard queries. Queries are often assigned to variables, so that they can be written once and referenced everywhere else.

Let’s take a look at variables in action in the upcoming sections.

## Variable Assignment

The `let` keyword is used to initialize and assign a variable. As a best practice, variable names conform to snake case. A variable defined using the `let` keyword can be referenced by using the `%` prefix. One exception to this is that Guard currently does not support referencing variables inside custom error messages. Some examples of variable assignments follow in sections below. 

### Static assignment

*Sample CloudFormation template*:

```yaml
Resources:
  EcsTask:
    Type: 'AWS::ECS::TaskDefinition'
    Properties:
      TaskRoleArn: '`arn:aws:iam::123456789012:role/my-role-name`'
```

*Sample Guard rule*:

```
rule check_ecs_task_definition_task_role_arn
{
    let ecs_task_definition_task_role_arn = 'arn:aws:iam::123456789012:role/my-role-name'
    Resources.*.Properties.TaskRoleArn == %ecs_task_definition_task_role_arn
}
```

In the example above, you are using the variable `ecs_task_definition_task_role_arn` to store a static string value. You author a rule that ensures that the Amazon Resource Name (ARN) of the role for the Amazon ECS task defined in the CloudFormation template is equal to the `arn:aws:iam::123456789012:role/my-role-name` string value.

### Query assignment

*Sample CloudFormation template*:

```yaml
Resources:
  EcsTask:
    Type: 'AWS::ECS::TaskDefinition'
    Properties:
      TaskRoleArn: 'arn:aws:iam::123456789012:role/my-role-name'
```

*Sample Guard rule*:

```
let ecs_tasks = Resources.*[
    Type == 'AWS::ECS::TaskDefinition'
]

rule check_ecs_task_definition_task_role_arn
{
    %ecs_tasks.Properties.TaskRoleArn == 'arn:aws:iam::123456789012:role/my-role-name'
}
```

In the example above, you are querying all resources of type `AWS::ECS::TaskDefinition` in the input template, and storing them in the `ecs_tasks` variable. The rule `check_ecs_task_definition_task_role_arn` then asserts that all resources of type `AWS::ECS::TaskDefinition` have `TaskRoleArn` set to `arn:aws:iam::123456789012:role/my-role-name`.

## Variable Referencing

Variables can also be referenced as a part of a query, e.g. `%ecs_tasks.Properties`. Guard would first evaluate the variable `ecs_tasks` and use values returned to traverse the hierarchy. If the variable `ecs_tasks` resolves to non-string values, then it is an error.

*Sample CloudFormation template*:

```yaml
Resources:
  EcsTask:
    Type: 'AWS::ECS::TaskDefinition'
    Properties:
      TaskRoleArn: 'arn:aws:iam::123456789012:role/my-role-name'
```

*Sample Guard rule*:

```
let ecs_tasks = Resources.*[
    Type == 'AWS::ECS::TaskDefinition'
]

rule check_ecs_task_definition_task_role_arn when %ecs_tasks !empty
{
    %ecs_tasks.Properties.TaskRoleArn == 'arn:aws:iam::123456789012:role/my-role-name'
}
```

In the example above, you are using the variable `ecs_tasks` to store the information for all resources of the type `AWS::ECS::TaskDefinition`  from the sample CloudFormation template. Then, the rule `check_ecs_task_definition_task_role_arn`, which is evaluated when the variable `ecs_tasks` is not empty - that is, at least one resource of type `AWS::ECS::TaskDefinition` exists in the template - asserts that the `TaskRoleArn` of all `AWS::ECS::TaskDefinition`  types in the template is `arn:aws:iam::123456789012:role/my-role-name`.

## Variable Scope

**Scope** refers to the visibility of variables defined in a rules file. As pointed out earlier, variables in Guard are single shot assignments. Also, there can only be one same named variable defined within the context of a scope. Broadly speaking, there are three places where a variable can be declared: file level, rule level and block level. Let’s take a look at those in sections below.
Broadly speaking, there are three places where a variable can be declared:

### File level

When a variable is initialized at a file level, usually at the top of the file, it can be used pretty much in all the rules within that file. It is visible (hence accessible) to the entire file.

The example below illustrates the use of a file-scoped variable.

*Sample CloudFormation template*:

```yaml
# Template-1
--- 
Resources: 
  EcsTask:
    Type: "AWS::ECS::TaskDefinition"
    Properties: 
      ExecutionRoleArn: "arn:aws:iam::123456789012:role/my-execution-role-name"
      TaskRoleArn: "arn:aws:iam::123456789012:role/my-task-role-name"
```

and a Guard rule set for the template, with rules that assert the `TaskRoleArn` and `ExecutionRoleArn` in the template as:

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

In the example above, `ecs_task_definition_task_role_arn` and `ecs_task_definition_execution_role_arn` are variables defined with file-level scope, and can be used across different rules in the rule set.

### Rule level

When a variable is initialized within a rule, it is visible only to the particular rule. Any references outside the rule will result in an error.

The example below illustrates the use of a rule scope variable.

Consider the template named `Template-1` in the example above. The rule set for the template can be rewritten to use variables having rule level scopes as:

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

In the rule set above, the variables `ecs_task_definition_task_role_arn` and `ecs_task_definition_execution_role_arn` have been moved to the individual rules where they are used, changing their scope from being file-level to being rule-level. Variables can now be accessed only in rules within which they have been defined, and not anywhere else.

### Block level

When a variable is initialized within a block, such as a `when` clause, it is only visible to the block. The outer rule or the file is unable to reference this variable. 

Consider the template named `Template-1` above. The rule set for the template can be rewritten to use variables having block-level scopes as:

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

In the rule set above, the variables `ecs_task_definition_task_role_arn` and `ecs_task_definition_execution_role_arn` have been moved to a type block definition for `AWS::ECS::TaskDefinition` in their individual rules. Variables will be visible only in their individual type blocks and nowhere outside of them.

## Example

Let’s walk through a more complex example of a production use case that allows for users to author Guard rules to ensure stricter controls on how their ECS tasks are defined. 

In the example below, you will write rules to ensure that each task definition conforms to the following:

1. Has a task and execution role attached
2. Both these roles are IAM roles
3. Both roles are described in the CloudFormation template 
4. A permission boundary exists for these roles


*Sample CloudFormation template:*

```yaml
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

*Sample Guard rule:*

```
`# Select as ECS TaskDefinitions from the template `
let ecs_tasks = Resources.*[
    Type == 'AWS::ECS::TaskDefinition'
]

`# Select a subset of TaskDefinitions whose TaskRoleArn is a Fn::Gett Ref`
let task_role_refs = some %ecs_tasks.Properties.TaskRoleArn.'Fn::GetAtt'[0]

`# Select a subset of TaskDefinitions whose ExecutionRoleArn is a Fn::Gett Ref`
let execution_role_refs = some %ecs_tasks.Properties.ExecutionRoleArn.'Fn::GetAtt'[0]

# Verifies #1 defined requirement
rule all_ecs_tasks_must_have_task_end_execution_roles 
    when %ecs_tasks !empty 
{
    %ecs_tasks.Properties {
        TaskRoleArn exists
        ExecutionRoleArn exists
    }
}

# Verifies requirement #2 and #3
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

# Verifies requirement #4
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