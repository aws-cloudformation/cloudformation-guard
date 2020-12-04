# Guard: A Language and tool to enforce "policy-as-code" for audit, compliance and overall system evaluation

Guard provides customers with simple language and associated tool that enables “policy-as-code” enforcement for customers. The tool is general enough to work with any structured payload (like JSON) to evaluate a set of rules against them to help audit security,i compliance or system system for the customer. The language is comprehensive to allow customers to write domain or industry specific rules but retains its simplificity of being human-readable and understandable, but machine enforceable. The accompanying tool is an implementation of the language that has a) built-in error diagnostics to guide customer with authoring rules; b) allows visualizing ruleset parse trees and relations; and works offline on laptop and server side in AWS services and CI/CD pipelines to provide end-2-end comprehensive experience for the customer.

# Tenets (unless you know better ones)

**Simple**: the language must be simple for customers to author rules, simple for IDE integrations, readable for human comprehension while being machine enforceable. The language can be explained on the back of a postcard. 

**Unambiguous**: the language must not allow for ambiguous interpretations that makes it hard to comprehend what is being evaluated. The tool is targeted for security and compliance related attestations that need the auditor to consistent and unambiguously understand rules and their evaluations.

**Comprehensive**: the language must be expressive to be applicable to model rules for a variety of domains that is cross-cutting industries. The language can be used to evaluate against any configuration management system across IaC, SaaS, PaaS, IoT or other domains. 

**Composable**: the language makes composition of higher order rule sets from multiple different rules sets simple with consistent interpretation and syntax. Composition should not add complexity to interpretation and customers can easily navigate across them.

**Extensible**: the language must provide for extensibility on top of the core language for domain specific extensions if it improves customer comprehension. The tools must make it easy for extensions to be installed and leveraged with secure authentication for them.   

# Language 

Gaurd's language is based on conjunctive normal form [Conjunctive Normal Form](https://en.wikipedia.org/wiki/Conjunctive_normal_form), a fancy way to say that the language is a set of logical ANDs across a set of logical ORs clauses. E.g. (A and B and C), where C = (D or F). Here is example of the language that demonstrates all the features of the language 

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
## Language Syntax 

### Rule Statement

Language compromises of a set of discrete rules defined within a file. Each rule block has the following syntax 

<pre>
<b>rule</b> <em>rule_name</em> [<b>when</b> <em>conditions</em>] {
    <em>clauses</em>
}
</pre>

Here, _rule_ keyword disgnates the start of a rule block. The keyword is followed by the *rule_name* that is a human readable name. When evaluating the rules file, the *rule_name* is displayed along with with status for the evalutaion PASS. FAiL or SKIP. The name followed by an optional gaurd conditions. When conditions act as a gaurd to determine if the rule is application for evaluation or must be skipped, a.k.a conditionally evalulated. We will do in depth about condtions later. 

The block then contains a set of clauses in Conjunctive Normal Form. To simplify specifying clauses and provide a consistent interpreation model, each clause present on its own newline provides an implicit AND clause in CNF. If the clause is joined with an "or" that is represents a disjunction or OR clause with the next one. E.g.
<pre>
<b>rule</b> <em>example</em> {

    <em>clause1</em>
    <em>clause2</em>
    
    <em>clause3</em> OR
    <em>clause4</em>
    
    <em>clause5</em> OR <em>clause6</em>
}
</pre>

represents ```clause1 AND clause2 AND (clause3 or clause4) AND (clause5 OR clause6)```

The language comprises of rules that are defined in blocks. Each block contains clauses in CNF form to be evaluated for the rule. A clause can reference other rules for decomposing complex evaluations. i) a simple but expressive query clause, ii) single assignment variables to value objects for both literal constants or from queries iii) value objects for string, regex, int, float, boolean for primitive types, and structued types composed of primitives, iv) collections of value objects r from queries, for literal and dynamic, property access notation on variables and incoming payload context, implicit ANDs with explicit ORs (CNF), and named rule references for composition is shown below.

