# Guard: A Language and tool to enforce "policy-as-code" for audit, compliance and overall system evaluation

Guard provides customers with simple language and associated tool that enables “policy-as-code” enforcement for customers. 
The tool is general enough to work with any structured payload (like JSON) to evaluate a set of rules against them 
to help audit security, compliance or overall system assessment for the customer. The language is comprehensive to 
allow customers to write domain or industry specific rules but retains the simplicity of being human-readable and 
understandable, but machine enforceable. The accompanying tool is an implementation of the language that has 
1. built-in error diagnostics to guide customer with authoring rules; 
2. allows visualizing ruleset parse trees and relations; and 
3.  works offline on laptop and server side in AWS services and CI/CD pipelines to provide end-2-end comprehensive experience

# Tenets (unless you know better ones)

**Simple**: the language must be simple for customers to author rules, simple for IDE integrations, readable for human 
comprehension while being machine enforceable. The language can be explained on the back of a postcard. 

**Unambiguous**: the language must not allow for ambiguous interpretations that makes it hard to comprehend what is 
being evaluated. The tool is targeted for security and compliance related attestations that need the auditor to 
consistent and unambiguously understand rules and their evaluations.

**Deterministic**: the language design must allow language implementers to have deterministic, consistent and isolated 
evalutions. Results for repeated evaluations for the same context and rule set must evaluate to the same result everytime.
Time to evaluate results inside near identical environments must be within acceptable tolerance limits.

**Comprehensive**: the language must be expressive to be applicable to model rules for a variety of domains that is 
cross-cutting industries. The language can be used to evaluate against any configuration management system across IaC, 
SaaS, PaaS, IoT or other domains. 

**Composable**: the language makes composition of higher order rule sets from multiple different rules sets simple with 
consistent interpretation and syntax. Composition should not add complexity to interpretation and customers can easily 
navigate across them.

**Extensible**: the language must provide for extensibility on top of the core language for domain specific extensions 
if it improves customer comprehension. The tools must make it easy for extensions to be installed and leveraged with 
secure authentication for them.   

# Language 

Gaurd's language is based on conjunctive normal form [Conjunctive Normal Form](https://en.wikipedia.org/wiki/Conjunctive_normal_form), 
a fancy way to say that the language is a set of logical ANDs across a set of logical ORs clauses. E.g. (A and B and C), 
where C = (D or F). Here is example of the language that demonstrates all the features of the language 

```
let global := [10, 20]                         # single assignment variables

rule example_rule when stage == 'prod' {
    let ec2_instance_types := [/^t*/, /^m*/]   # scoped variable assignments

    # clause can referene another rule for composition
    dependent_rule                            # named rule reference

    # IN (disjunction, one of them)
    AWS::EC2::Instance InstanceType IN %ec2_instance_types

    # Block groups for evaluating groups of clauses together. 
    # The "type" "AWS::EC2::Instance" is static 
    # type information that help validate if access query inside the block is 
    # valid or invalid
    AWS::EC2::Instance {                          # Either an EBS volume
        let volumes := block_device_mappings      # var local, snake case allowed.
        when %volumes.*.Ebs != null {                  # Ebs is setup
          %volumes.*.device_name == /^\/dev\/ebs-/  # must have ebs in the name
          %volumes.*.Ebs.encryped == true               # Ebs volume must be encryped
          %volumes.*.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
        }
    } or
    AWS::EC2::Instance {                   # OR a regular volume (disjunction)
        block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc
    }
}

rule dependent_rule { ... }

```

- [Language Syntax](language-syntax.md)
- [Query](query-RFC.md)
- [CloudFormation Examples](cloudformation/examples.md)


