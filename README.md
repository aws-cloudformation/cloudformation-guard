# AWS CloudFormation Guard

AWS CloudFormation Guard (Guard) is an open-source general-purpose policy-as-code evaluation tool. It provides developers with a simple-to-use, yet powerful and expressive domain-specific language (DSL) to define policies and enables developers to validate JSON- or YAML-formatted structured data with those policies. 

Guard 2.0 is a complete re-write of the earlier 1.0 version to make the tool general-purpose. With Guard 2.0, you're no longer limited to writing policies for only CloudFormation templates. 

For more information about Guard, see [What is Guard?](docs/what-is.md). To get started with writing rules, testing rules, or validating JSON- or YAML-formatted data against rules, see [Getting started](docs/getting-started.md).

> **NOTE**: If you are using Guard 1.0, we highly recommend adopting Guard 2.0 because Guard 2.0 is a major release that introduces multiple features to simplify your current policy-as-code experience. Guard 2.0 is backward incompatible with your Guard 1.0 rules and can result in breaking changes. For information about migrating Guard rules, see [Migrating 1.0 rules to 2.0](docs/what-is.md#migrate-rules-how-to).
> 
> You can find code related to Guard2.0 on the main branch of the repo and code related to Guard 1.0 on the [Guard1.0 branch](https://github.com/aws-cloudformation/cloudformation-guard/tree/Guard1.0) of the repo.

**Guard In Action**

![Guard In Action](images/guard-demo.gif)

## Table of Contents

* [FAQs](#faqs)
* [Guard DSL](#guard-dsl)
  * [Tenets](#tenets)
  * [Features of Guard DSL](#features-of-guard-dsl)
* [Installation](#installation)
  * [How does Guard CLI work?](#how-does-guard-cli-work?)
* [License](#license)

## FAQs

**1) What is Guard?**
> Guard is an open-source command line interface (CLI) that provides developers with a general purpose domain-specific language (DSL) to express policy-as-code and then validate their JSON- and YAML-formatted data against that code. Guard’s DSL is a simple, powerful, and expressive declarative language to define policies. It is built on the foundation of clauses, which are assertions that evaluate to `true` or `false`. Examples clauses can include simple validations, like requiring that all Amazon Simple Storage Service (S3) buckets must have versioning enabled. You can also combine clauses to express complex validations, like preventing public network reachability of Amazon Redshift clusters placed in a subnet. Guard supports looping, queries with filtering, cross-query joins, one-shot variable assignments, conditional executions, and composable rules. These features help developers to express simple and advanced policies for various domains. For more information about Guard, see [What is Guard?](docs/what-is.md).

**2) What Guard is not?**
> Guard **is not** a general-purpose programming language. It is a purpose-built DSL that is designed for policy definition and evaluation. Both non-technical people and developers can easily pick up Guard. Guard is human-readable and machine enforceable.

**3) When can I use Guard?**
> You can use Guard to define any type of policy for evaluation. For information about business domains in which Guard rules are useful, see [Features of Guard](docs/what-is.md#servicename-feature-overview).

**3) What is a clause in Guard?**
> A clause is an assertion that evaluates to true or false. For more information about clauses, see [Writing rules](docs/writing-rules.md). 

**4) What are the supported** **types** **that can I use to define clauses?**
> For a list of supported types, see [the query|value literal property of Guard rule clauses](docs/writing-rules.md#clauses-properties-value-literal).

**5) What binary and unary comparison operators can I use?**
> For a list of supported binary and unary comparison operators, see [the operator property of Guard rule clauses](docs/writing-rules.md#clauses-properties-operator).

**6) How can I define advanced policy rules?**
> You can define advanced policy rules using Conjunctive Normal Form. For more information about defining advanced poilcy rules, see [Defining queries and filtering](docs/query-and-filtering.md).

**7) Can I easily test policy rules?**
> Yes. Guard supports a built-in unit testing framework to test policy rules and clauses. This gives customers confidence that their Guard policy rules work as intended. For more information about the unit testing framework, see [Testing Guard rules](docs/testing-rules.md).

**8)** **Does Guard support rule categories?**
> Yes. Guard supports running several rule sets together for validating policies. You can create multiple rules files, each with its own intended purpose. For example, you can create one rules file for Amazon S3, a second one for Amazon DynamoDB, a third one for access management, and so on. Alternatively, you can create a rules file for all of your security related rules, a second one for cost compliance, and so on. You can use Guard to validate all of these rules files. For more information about rule sets, see [Composing named-rule blocks](docs/named-rule-block-composition.md).

**9) When can I evaluate Guard policies?**
> Guard supports the entire spectrum of end-to-end evaluation of policy checks. The tool supports bringing in shift-left practices as close as running it directly at development time, integrated into code repositories via hooks like GitHub Actions for pull requests, and into CI/CD pipelines such as AWS CodePipeline pipelines and Jenkins (just exec process).

**10) What are you not telling me? This sounds too good to be true.**
> Guard is a DSL and an accompanying CLI tool that allows easy-to-use definitions for declaring and enforcing policies. Today the tool supports local file-based execution of a category of policies. Guard doesn’t support the following things today, along with workarounds for some:
>
> 1. Sourcing of rules from external locations such as GitHub Release and S3 bucket. If you want this feature natively in Guard, please raise an issue or +1 an existing issue.
> 2. Ability to import Guard policy file by reference (local file or GitHub, S3, etc.). It currently only supports a directory on disk of policy files, that it would execute. 
> 3. Parameter/Vault resolution for IaC tools such as CloudFormation or Terraform. Before you ask, the answer is NO. We will not add native support in Guard as the engine is general-purpose. If you need CloudFormation resolution support, raise an issue and we might have a solution for you. We do not support HCL natively. We do, however, support Terraform Plan in JSON to run policies against for deployment safety. If you need HCL support, raise an issue as well.
> 4. Ability to reference variables like `%s3_buckets`, inside error messages. Both JSON/Console output for evaluation results contain some of this information for inference. We also do not support using variable references to create dynamic regex expressions. However, we support variable references inside queries for cross join support, like `Resources.%references.Properties.Tags`.  
> 5. Support for specifying variable names when accessing map or list elements to cature these values. For example, consider this check `Resources[resource_name].Properties.Tags not empty`, here `resource_name` captures the key or index value. The information is tracked as a part of the evaluation context today and  present in both console/JSON outputs. This support will be extended to regex expression variable captures as well.
> 6. There are some known issues with potential workarounds that we are tracking towards resolution. For information about known issues, see [Troubleshooting Guard](docs/troubleshooting.md).

**11) What are we really thankful about?**
> Where do we start? Hmm.... we want to thank Rust [language’s forums](https://users.rust-lang.org/), [build management, and amazing ecosystem](https://crates.io/) without which none of this would have been possible. We are not the greatest Rust practitioners, so if we did something that is not idiomatic Rust, please raise a PR. 
>
> We want to make a special mention to [nom](https://github.com/Geal/nom) combinator parser framework to write our language parser in. This was an excellent decision that improved readability, testability, and composition. We highly recommend it. There are some rough edges, but it’s just a wonderful, awesome library. Thank you. Apart from that, we are consumers of many crates including [hyper](https://crates.io/crates/hyper) for HTTP handling, [simple logger](https://crates.io/crates/simple_logger), and many more. We also want to thank the open-source community for sharing their feedback with us through GitHub issues/PRs.
>
> And of course AWS for supporting the development and commitment to this project. Now read the docs and take it for a ride and tell us anything and everything.

## Guard DSL

### Tenets 

**(Unless you know better ones)**

These tenets help guide the development of the Guard DSL:

* **Simple**: The language must be simple for customers to author policy rules, simple to integrate with an integrated development environment (IDE), readable for human comprehension, and machine enforceable. 

* **Unambiguous**: The language must not allow for ambiguous interpretations that make it hard for customers to comprehend the policy evaluation. The tool is targeted for security and compliance related attestations that need the auditor to consistently and unambiguously understand rules and their evaluations.

* **Deterministic**: The language design must allow language implementations to have deterministic, consistent, and isolated evaluations. Results for repeated evaluations for the same context and rules must evaluate to the same result every time. Time to evaluate results inside near-identical environments must be within acceptable tolerance limits.

* **Composable**: The language must support composition to help build higher order functionality such as checks for PCI compliance, by easily combining building blocks together. Composition should not increase the complexity for interpreting outcomes, syntax, or navigation.

### Features of Guard DSL

* **Clauses:** Provides the foundational underpinning for Guard. They are assertions that evaluate to true or false. You can combine clauses using [Conjunctive Normal Form](https://en.wikipedia.org/wiki/Conjunctive_normal_form). You can use them for direct assertions, as part of filters to select values, or for conditional evaluations. To learn more read [Writing rules](docs/writing-rules.md).

* **Context-Aware Evaluations, `this` binding and Loops:** Automatic binding for context values when traversing hierarchical data with support for implicit looping over collections with an easy-to-use syntax. Collections can arise from accessing an array of elements, values for a map along with a filter, or from a query. To learn more, see [Writing clauses to perform context-aware evaluations](docs/context-aware-evaluations.md).

* **Query & Filtering:** Queries support simple decimal dotted format syntax to access properties in the hierarchical data. Arrays/Collections are accessed using `[]` . Map or Struct’s values can use `*` for accessing values for all keys. All collections can be further narrowed to target specific instances inside the collection using filtering. To learn more, see [Defining queries and filtering](docs/query-and-filtering.md).

* **Variables, Projections, and Query Interpolation:** Guard supports single shot assignment to variables using a **`let`** keyword for assignment. All variable assignments resulting from a query is a list (result set). One can also assign static literals to variables. Variables are assessed using a prefix **`%`** and can be used inside the Query for interpolation. To learn more, see [Assigning and referencing variables in Guard rules](docs/variables.md).

* **Complex Composition**: As stated earlier, clauses can be expressed in Conjunctive Normal Form. Clauses on separates lines are ANDs. Disjunctions are expressed using the `or|OR` keyword. You can group clauses in a named rule. You can then use named rules in other rules to create more advanced compositions. Furthermore, you can have multiple files containing named rules that together form a category of checks for a specific compliance like “ensure encryption at rest”. To learn more, see [Composing named-rule blocks](docs/complex-composition.md).

## Installing the Guard CLI

For information about installing Guard, see [Setting up Guard](docs/setting-up.md).

### How does the Guard CLI work?

For information about using Guard CLI commands, see [Guard CLI command reference](docs/cfn-guard-command-reference.md).

## License

This project is licensed under the Apache-2.0 License.
