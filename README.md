# AWS CloudFormation Guard

**Validate Cloud Environments with Policy-as-Code**

AWS CloudFormation Guard is an open-source general-purpose policy-as-code evaluation tool. It provides developers with a simple-to-use, yet powerful and expressive domain-specific language (DSL) to define policies and enables developers to validate JSON- or YAML- formatted structured data with those policies.

The Guard 3.0 release introduces support for stateful rules through built-in functions, SAM CLI as an alternative deployment method for `cfn-guard-lambda`, command auto-completions for shell, advanced regular expressions, improved handling of intrinsic functions for the test command, as well as the `--structured` flag to the validate command to emit JSON/YAML parseable output. Note that previously written tests may have to be reviewed due to the corrected behavior of intrinsic function handling. Please see the release notes for full details and examples.

Guard can be used for the following domains:

1. **Preventative Governance and Compliance (shift left):** validate Infrastructure-as-code (IaC) or infrastructure/service compositions such as CloudFormation Templates, CloudFormation ChangeSets, Terraform JSON configuration files, Kubernetes configurations, and more against Guard policies representing your organizational best practices for security, compliance, and more. For example, developers can use Guard policies with
   1. Terraform plan (**in JSON format**) for deployment safety assessment checks or Terraform state files to detect live state deviations.
   2. Static assessment of IaC templates to determine network reachability like Amazon Redshift cluster deployed inside a VPC and prevent the provision of such stacks.
2. **Detective Governance and Compliance:** validate conformity of Configuration Management Database (CMDB) resources such as AWS Config-based configuration items (CIs). For example, developers can use Guard policies against AWS Config CIs to continuously monitor state of deployed AWS and non-AWS resources, detect violations from policies, and trigger remediation.
3. **Deployment Safety:** validate CloudFormation ChangeSets to ensure changes are safe before deployment. For example, renaming an Amazon DynamoDB Table will cause a replacement of the Table. With Guard 3.0, you can prevent such changes in your CI/CD pipelines.

> **NOTE**: If you are using Guard 1.0 rules, we highly recommend adopting the latest version of Guard to simplify your current policy-as-code experience. Guard 2.0 and higher versions are backward incompatible with your Guard 1.0 rules and can result in breaking changes. The Guard 2.0 release was a complete re-write of the earlier 1.0 version to make the tool general-purpose.
>
> To migrate from Guard 1.0 rules to use the updated grammar, follow the steps given below.
>
> 1. Pull the release artifacts for the latest `2.x.x` release from the corresponding release page listed [here](https://github.com/aws-cloudformation/cloudformation-guard/releases).
> 2. Use `migrate` command to transition your existing 1.0 rules to use the updated grammar
> 3. Read about all new Guard features from the latest release, and modify your rules for enhanced experience

**Guard In Action**

![Guard In Action](images/guard-demo.gif)

**Customer Feedback**
Take this [survey](https://amazonmr.au1.qualtrics.com/jfe/form/SV_bpyzpfoYGGuuUl0) to provide feedback about cfn-guard

## Table of Contents

<!-- no toc -->

- [FAQs](#faqs)
- [Guard DSL](#guard-dsl)
  - [Tenets](#tenets)
  - [Features of Guard DSL](#features-of-guard-dsl)
- [Guard CLI](#guard-cli)
  - [Installation](#installation)
  - [How does Guard CLI work?](#how-does-guard-cli-work?)
- [Rule authoring references](#references)
- [Built-in functions & stateful rules](#functions)
- [AWS Rule Registry](#registry)
- [Use Guard as a Docker Image](#docker)
- [Use Guard as a Github Action](https://github.com/aws-cloudformation/cloudformation-guard/tree/main/action#readme)
- [Use Guard as a CI tool](#ci)
- [Use Guard as a pre-commit hook](#pre-commit-hook)
- [Contribute using the DevContainer in VSCode](#devcontainer)
- [License](#license)

## FAQs

**1) What is Guard?**

> Guard is an open-source command line interface (CLI) that provides developers a general purpose domain-specific language (DSL) to express policy-as-code and then validate their JSON- and YAML-formatted data against that code. Guard’s DSL is a simple, powerful, and expressive declarative language to define policies. It is built on the foundation of clauses, which are assertions that evaluate to `true` or `false`. Examples clauses can include simple validations like all Amazon Simple Storage Service (S3) buckets must have versioning enabled, or combined to express complex validations like preventing public network reachability of Amazon Redshift clusters placed in a subnet. Guard has support for looping, queries with filtering, cross query joins, single shot variable assignments, conditional executions, and composable rules. These features help developers to express simple and advanced policies for various domains.

**2) What Guard is not?**

> Guard **is not** a general-purpose programming language. It is a **purpose-built** DSL that is designed for policy definition and evaluation. Both non-technical people and developers can easily pick up Guard. Guard is human-readable and machine enforceable.

**3) Where can I use Guard?**

> You can use Guard to define any type of policy for evaluation. You can apply Guard in the context of multiple domains: a) validating IaC/service compositions such as [CloudFormation Templates](https://aws.amazon.com/cloudformation/resources/templates/), Terraform JSON configuration files, and Kubernetes configurations, b) verifying conformity of CMDB resources such as AWS Config-based CIs, and c) assessing security postures across resources like AWS Security Hub. The policy language and expression is common to all of them, based on simple Guard clauses.

**3) What is a clause in Guard?**

> Clause is an assertion that evaluates to true or false. Clauses can either use binary operations to compare two values (e.g `==, >` and `in`), or unary operations that takes only one value (e.g. `exists, empty,` and `is_list`). Here is a sample clause that compares `Type` to be a `AWS::S3::Bucket` :

```
Type == /AWS::S3::Bucket/
```

**4) What are the supported** **types** **that can I use to define clauses?**

> Guard supports all primitives `string, integer (64), float (64), bool, char, regex` and specialized range expression like `r(10, 200)`, for specifying ranges of values. It supports general key value pair maps (a.k.a associative arrays/struct) like `{ "my-map": { "nested-maps": [ { "key": 10, "value": 20 } ] } },` and arrays of primitives or key-value pair maps like `[10, 20, 30] or [{ Key: "MyApp", Value: "PROD}, ..]`.

**5) What binary and unary comparison operators can I use?**

> _Unary Operators:_ `exists, empty, is_string, is_list, is_struct, is_bool, is_int, is_float, not(!)` > _Binary Operators:_ `==, !=, >, >=, <, <=, IN `
>
> Most operators are self-explanatory. A few important points:
>
> 1. Refer [Guard: Clauses](docs/CLAUSES.md) to understand the usage of `exists` and `empty` operators
> 2. Clause `ports >= [10, 20, 30]` implies that every element for `ports` is `>= 30`. If your intention is range, then express it as `r[10, 30]` .
> 3. Clause `ports >= 100` can have ports resolve to an array `[121, 200, 443]`. This check ensures that every element returned was >= 100, and in the example shown this evaluates to `true.`
> 4. `IN` operator for collections (does not work for `string` type) to check if any value matches. For example:

```
Properties.SslPolicy IN ["ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06"]
```

**6) How can I define advanced policy rules?**

> You can define advanced policy rules using Conjunctive normal form. For example, here is a clause that asserts that all S3 buckets have a) names that start with a common prefix, b) encryption turned on, and c) only KMS-based algorithm is used (to know more about the query part read [Guard: Query and Filtering](docs/QUERY_AND_FILTERING.md)) for IaC template.

```
let s3_buckets = Resources.*[ Type == /S3::Bucket/ ]

# Skip the checks if there are no S3 buckets present
rule s3_bucket_name_encryption_check when %s3_buckets !empty {
    %s3_buckets {
        Properties {
             # common prefix
             BucketName == /^MyCompanyPrefix/

             # encryption MUST BE on
             BucketEncryption.ServerSideEncryptionConfiguration[*] {
                # only KMS
                ServerSideEncryptionByDefault.SSEAlgorithm IN
                    ["aws:KMS"]
             }
        }
    }
}
```

**7) Can I easily test policy rules?**

> Yes. Guard supports a built-in unit testing framework to test policy rules and clauses. This gives customers confidence that their guard policy rules work as intended. You can learn more about this unit testing framework in this doc [Guard: Unit Testing](docs/UNIT_TESTING.md)

**8)** **Does Guard support rule categories?**

> Yes. Guard supports running several rule-sets together for validating policies. You can create multiple rule files, each with its own intended purpose. For example, you can create one rules file for S3, second one for Dynamo DB, third one for access management, and so on. Alternatively, you can create a rules file for all your security related rules, second one for cost compliance, and so on. You can run Guard against all these rule files at once for evaluation. Refer example rules file [Guard: Clauses](docs/CLAUSES.md), [Guard: Complex Composition](docs/COMPLEX_COMPOSITION.md).

**9) Where can I evaluate Guard policies?**

> Guard supports the entire spectrum of end-to-end evaluation of policy checks. The tool supports bringing in shift-left practices as close as running it directly at development time, integrated into code repositories via hooks like GitHub Actions for pull requests, and into CI/CD pipelines such as AWS CodePipeline pipelines and Jenkins (just exec process).

**10) What are you not telling me? This sounds too good to be true.**

> Guard is a DSL and an accompanying CLI tool that allows easy-to-use definitions for declaring and enforcing policies. Today the tool supports local file-based execution of a category of policies. Guard doesn’t support the following things today, along with workarounds for some:
>
> 1. Sourcing of rules from external locations such as GitHub Release and S3 bucket. If you want this feature natively in Guard, please raise an issue or +1 an existing issue.
> 2. Ability to import Guard policy file by reference (local file or GitHub, S3, etc.). It currently only supports a directory on disk of policy files, that it would execute.
> 3. Parameter/Vault resolution for IaC tools such as CloudFormation or Terraform. Before you ask, the answer is NO. We will not add native support in Guard as the engine is general-purpose. If you need CloudFormation resolution support, raise an issue and we might have a solution for you. We do not support HCL natively. We do, however, support Terraform Plan in JSON to run policies against for deployment safety. If you need HCL support, raise an issue as well.
> 4. Ability to reference variables like `%s3_buckets`, inside error messages. Both JSON/Console output for evaluation results contain some of this information for inference. We also do not support using variable references to create dynamic regex expressions. However, we support variable references inside queries for cross join support, like `Resources.%references.Properties.Tags`.
> 5. Capturing what a filter selected under a variable name, as in `Resources[ resource_name | Type == 'AWS::S3::Bucket' ].Properties.Tags not empty`, is supported, and `%resource_name` can be read by later clauses in the same scope. One contract on every path: a capture over a map's entries binds the entries' keys (here the logical ids, also through a wildcard such as `Resources[*][ name | ... ]` and through a variable holding `Resources.*[ ... ]`), and a capture over a list binds the selected elements themselves (`Tags[ t | Key == 'Name' ]` binds the tag, so `%t.Value` reads its value). A map that is one object rather than a collection of entries -- a map one of whose entries is a scalar, such as an IAM `Statement` written as a single statement -- followed by a filter is bound as an element is: `Statement[ s ][ Effect == 'Allow' ]` and `Statement[*][ s | Effect == 'Allow' ]` both bind the statement itself, whether it is written as one object or as a one-element list, so `%s.Action` reads its action either way. A capture name is scoped to the block it is written in and to each resource of a type block. Using a captured value as an interpolated key, `Resources.%name`, requires it to be a string. See [Query and Filtering](docs/QUERY_AND_FILTERING.md#capturing-what-a-filter-selected).
> 6. There are [known issues](docs/KNOWN_ISSUES.md) with potential workarounds that we are tracking towards resolution

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

- **Simple**: The language must be simple for customers to author policy rules, simple to integrate with an integrated development environment (IDE), readable for human comprehension, and machine enforceable.

- **Unambiguous**: The language must not allow for ambiguous interpretations that make it hard for customers to comprehend the policy evaluation. The tool is targeted for security and compliance related attestations that need the auditor to consistently and unambiguously understand rules and their evaluations.

- **Deterministic**: The language design must allow language implementations to have deterministic, consistent, and isolated evaluations. Results for repeated evaluations for the same context and rules must evaluate to the same result every time. Time to evaluate results inside near-identical environments must be within acceptable tolerance limits.

- **Composable**: The language must support composition to help build higher order functionality such as checks for PCI compliance, by easily combining building blocks together. Composition should not increase the complexity for interpreting outcomes, syntax, or navigation.

### Features of Guard DSL

- **Clauses:** Provides the foundational underpinning for Guard. They are assertions that evaluate to true or false. You can combine clauses using [Conjunctive Normal Form](https://en.wikipedia.org/wiki/Conjunctive_normal_form). You can use them for direct assertions, as part of filters to select values, or for conditional evaluations. To learn more read [Guard: Clauses](docs/CLAUSES.md)

- **Context-Aware Evaluations, `this` binding and Loops:** Automatic binding for context values when traversing hierarchical data with support for implicit looping over collections with an easy-to-use syntax. Collections can arise from accessing an array of elements, values for a map along with a filter, or from a query. To learn more read [Guard: Context-Aware Evaluations, this and Loops](docs/CONTEXTAWARE_EVALUATIONS_AND_LOOPS.md)

- **Query & Filtering:** Queries support simple decimal dotted format syntax to access properties in the hierarchical data. Arrays/Collections are accessed using `[]` . Map or Struct’s values can use `*` for accessing values for all keys. All collections can be further narrowed to target specific instances inside the collection using filtering. To learn more read [Guard: Query and Filtering](docs/QUERY_AND_FILTERING.md)

- **Variables, Projections, and Query Interpolation:** Guard supports single shot assignment to variables using a **`let`** keyword for assignment. All variable assignments resulting from a query is a list (result set). One can also assign static literals to variables. Variables are assessed using a prefix **`%`** and can be used inside the Query for interpolation. To learn more read [Guard: Query, Projection and Interpolation](docs/QUERY_PROJECTION_AND_INTERPOLATION.md)

- **Complex Composition**: As stated earlier, clauses can be expressed in Conjunctive Normal Form. Clauses on separates lines are ANDs. Disjunctions are expressed using the `or|OR` keyword. You can group clauses in a named rule. You can then use named rules in other rules to create more advanced compositions. Furthermore, you can have multiple files containing named rules that together form a category of checks for a specific compliance like “ensure encryption at rest”. To learn more read [Guard: Complex Composition](docs/COMPLEX_COMPOSITION.md)

## Guard CLI

### Installation

#### Installation from Pre-Built Release Binaries

##### MacOS

By default this is built for macOS-12 (Monterey). See [OS Matrix](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#github-hosted-runners)

1. Open terminal of your choice. Default `Cmd+Space`, type `terminal`
2. Cut-n-paste the commands below (default latest, add `-s -- -v <VERSION>` for other versions ie. `-s -- -v 3.1.2`)

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/aws-cloudformation/cloudformation-guard/main/install-guard.sh | sh
```

Remember to add `~/.guard/bin/` to your `$PATH`.

Alternatively, you can install the latest version with [Homebrew](https://brew.sh/).

```bash
$ brew install cloudformation-guard
```

You would not need to modify `$PATH` this way.

##### Ubuntu

1. Open any terminal of your choice
2. Cut-n-paste the commands below (default latest, add `-s -- -v <VERSION>` for other versions ie. `-s -- -v 3.1.2`)

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/aws-cloudformation/cloudformation-guard/main/install-guard.sh | sh
```

Remember to add `~/.guard/bin/` to your `$PATH`.

##### Windows

1. Open PowerShell as Administrator
2. Cut-n-paste the command below

```shell
$GuardWindowsInstallScript = Invoke-WebRequest https://raw.githubusercontent.com/aws-cloudformation/cloudformation-guard/main/install-guard.ps1; Invoke-Expression $($GuardWindowsInstallScript.Content)
```

If you get an error regarding authorization to execute the script run the follow before retrying step 2:

```shell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

#### Installation of Rust and Cargo

##### Ubuntu/MacOS: Install Rust and Cargo

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you have not already, run `source $HOME/.cargo/env` as recommended by the rust installer. Read [here](https://rustup.rs/) for more information.

If building on `Ubuntu`, it is recommended to run `sudo apt-get update; sudo apt install build-essential`.

##### Windows 10: Install Rust and Cargo

1. Create a Windows 10 workspace.
2. Install the version of Microsoft Visual C++ Build Tools 2019 which provides just the Visual C++ build tools: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019.
3. Download the installer and run it.
4. Select the "Individual Components" tab and check "Windows 10 SDK".
5. Select the "Language Packs" tab and make sure that at least "English" is selected.
6. Click "Install".
7. Let it download and reboot if asked.
8. Install [Rust](https://forge.rust-lang.org/infra/other-installation-methods.html#other-ways-to-install-rustup).
9. Download [rust-init.exe](https://static.rust-lang.org/rustup/dist/i686-pc-windows-gnu/rustup-init.exe).
10. Run it and accept the defaults.

#### Cargo-based Installation

Now that you have [rust and cargo installed](https://doc.rust-lang.org/cargo/getting-started/installation.html), installation of cfn-guard is easy:

```bash
$ cargo install cfn-guard
```

Check `help` to see if it is working.

```bash
$ cfn-guard help
cfn-guard 3.1.2

  Guard is a general-purpose tool that provides a simple declarative syntax to define
  policy-as-code as rules to validate against any structured hierarchical data (like JSON/YAML).
  Rules are composed of clauses expressed using Conjunctive Normal Form
  (fancy way of saying it is a logical AND of OR clauses). Guard has deep
  integration with CloudFormation templates for evaluation but is a general tool
  that equally works for any JSON- and YAML- data.

Usage: cfn-guard [COMMAND]

Commands:
  parse-tree   Prints out the parse tree for the rules defined in the file.
  test         Built in unit testing capability to validate a Guard rules file against
               unit tests specified in YAML format to determine each individual rule's success
               or failure testing.

  validate     Evaluates rules against the data files to determine success or failure.
               You can point rules flag to a rules directory and point data flag to a data directory.
               When pointed to a directory it will read all rules in the directory file and evaluate
               them against the data files found in the directory. The command can also point to a
               single file and it would work as well.
               Note - When pointing the command to a directory, the directory may not contain a mix of
               rules and data files. The directory being pointed to must contain only data files,
               or rules files.

  rulegen      Autogenerate rules from an existing JSON- or YAML- formatted data. (Currently works with only CloudFormation templates)
  completions  Generate auto-completions for all the sub-commands in shell.
  help         Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

```

### How does Guard CLI work?

The two common Guard CLI commands are `validate` and `test`.

#### Validate

Validate command is used when you need to assess the compliance or security posture as defined by a set of policy files against incoming JSON/YAML data. Common data payloads used are CloudFormation Templates, CloudFormation ChangeSets, Kubernetes Pod policies, Terraform Plan/Configuration in JSON format, and more. Here is an example run of the `validate` command for assessing Kubernetes Pod Container configurations

1. Save the sample policy rules file below as `k8s-pod-containers-limits.guard`:

```
#
# Kubernetes container based limit checks
#

#
# These set of rules primarily apply to the version 1 of the API spec (including v1Beta) and
# the kind of document is a 'Pod'
#
rule version_and_kind_match
{
    apiVersion == /v1/
    kind == 'Pod'
}

#
# For the 'Pod' document ensure that containers have resource limits set
# for memory
#
rule ensure_container_has_memory_limits when version_and_kind_match
{
    spec.containers[*]
    {
       resources.limits
       {
            #
            # Ensure that memory attribute is set
            #
            memory exists
            <<
                Id: K8S_REC_22
                Description: Memory limit must be set for the container
            >>
        }
   }

}

#
# For the 'Pod' document ensure that containers have resource limits set
# for cpu
#
rule ensure_container_has_cpu_limits when version_and_kind_match
{
    spec.containers[*]
    {
       resources.limits
       {
            #
            # Ensure that cpu attribute is set
            #
            cpu exists
            <<
                Id: K8S_REC_24
                Description: Cpu limit must be set for the container
            >>
       }
   }
}
```

2. Paste the command below and hit `enter`

```bash
cfn-guard validate -r k8s-pod-containers-limits.guard
```

3. Cut-n-paste the sample configuration below for k8s pods on STDIN and then hit `CTRL+D`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: frontend
spec:
  containers:
    - name: app
      image: "images.my-company.example/app:v4"
      resources:
        requests:
          memory: 64Mi
          cpu: 0.25
        limits:
          memory: 128Mi
    - name: log-aggregator
      image: "images.my-company.example/log-aggregator:v6"
      resources:
        requests:
          memory: 64Mi
          cpu: 0.25
        limits:
          memory: 128Mi
          cpu: 0.75
```

![Execution of validate](images/guard-validate.png)

The container `app` does not contain CPU limits specified, which fails the overall evaluation as shown in the screenshot.

#### Input formats

`validate`, `test` and `rulegen`, and the library entry point `run_checks` that guard-ffi and guard-lambda call, read JSON and YAML data with one YAML reader, so a document means the same thing whichever of them reads it. JSON is read as the YAML it is, with these particulars:

* A JSON string that spells a character outside the Basic Multilingual Plane as a surrogate-pair escape (two `\u` escapes, a high surrogate then a low one, which is how Python's `json.dumps` writes 😀 by default) is read as that character. The same escape in a YAML document is refused, because YAML writes that character as `\U0001F600`.
* A raw U+0085 (NEL), U+2028 (LS) or U+2029 (PS) inside a JSON string is read as that character. JSON permits all three unescaped; the YAML reader on its own treats each as a line break and folds it, so `"a<NEL>b"` would have read as `a b`.
* Positions in a report are those of the source text, numbered as the YAML reader numbers lines: CR, LF and CRLF end a line, and so do NEL, LS and PS, even inside a JSON string. Text after one of those three on the same physical line is reported on the next line, which is also how the excerpt beside a finding counts.
* Three more shapes of valid JSON fall outside what the YAML reader's scanner accepts, and are rewritten the way a YAML emitter would write them before the reader sees the text, so the document reads as written: a member name that spans more than 1024 bytes from its opening quote to its colon is read as an explicit key, a line break between a member name and its colon as a space, and a raw U+007F-U+009F character (other than U+0085) or U+FFFE or U+FFFF inside a string as that character. The one shape still refused, with a message that says the document is valid JSON and names it, is a lone surrogate escape (`\uD800` with no low surrogate after it), which is not a character.
* Text that is neither YAML nor JSON (a missing comma between two members, say) is refused with the YAML reader's message and the position where it stopped. When the text begins with `{` or `[` and the JSON reader got at least as far, the JSON reader's own refusal follows on a second line, labeled `Read as JSON as well, the text fails with:`, with its line and column in its own terms (line feeds and bytes, where the YAML reader counts every line break and characters). YAML flow style begins with `{` or `[` too, and a JSON reader stops at its first unquoted key, which is valid YAML and not the mistake, so a JSON position that is earlier than the YAML reader's is not shown; nor is anything from the JSON reader shown for text that begins any other way.
* YAML anchors and aliases resolve on every route, within the budget: a template given to `validate` or `rulegen`, a `test` file, and the data handed to `run_checks`. An alias is a copy of the anchored node, and the copies a document makes are bounded, in nodes and in bytes; a `test` file has that budget per case, with a ceiling over the whole file. The refusals are the same on every route: an alias to an anchor that no earlier node declares, a copy past the budget, a copy that would nest past the reader's depth bound, and an anchor that would take what the document's anchors hold, together, past the budget plus the document's own size (an anchor nested inside another is held once on its own and once inside each anchor around it). See [docs/UNIT_TESTING.md](docs/UNIT_TESTING.md) for the figures.
* An explicit `!!int` tag resolves by the same forms as a plain scalar, so `!!int 0o755` and `!!int 0x1ED` are both the integer 493. The tagged reading used to be decimal only: a document carrying either spelling was refused as a bad value and the run exited 5, while the same document with the tag removed loaded and the rules ran. A tagged decimal with a redundant leading zero is refused when YAML 1.1 and YAML 1.2 read it as different numbers, `!!int 0755` being octal 493 to one and decimal 755 to the other, with a message naming both integers; where the two agree it loads, so `!!int 007` is 7, and as a mapping key `!!int 007:` is the key `7` where it used to be refused.
* A tagged scalar that its `!!` tag cannot read is refused with the node as the document wrote it, tag included: `Value = !!int x` or `Value = !!float x`, where the refusal used to carry the payload alone as `Value = x`. The same text is what the `test` command's json, junit and yaml reports carry for such an input, so a consumer that matched the old string sees the new one.
* `validate` warns on stderr, one line per key, when a key merged in through `<<` collides with a key the mapping already holds in another form (the integer `1` beside the string `"1"`, say): the held value stands, and the line says which of the two is the one evaluated. Such a merged key used to be dropped in silence. The line has the same shape as the one for a key written twice in one mapping, which `test` writes as before for a case's `input`, naming the test file; in every case the verdict and the exit code do not move.
* A merge key reached through an alias (`&m <<:` written once, `*m:` used as a key elsewhere) is the merge key its anchor is: the mapping under it merges into the mapping that carries it, as under a written `<<`, and when it is given anything but a mapping or a sequence of mappings (`*m: abc`) the document is refused as a written `<<: abc` is. Such an alias used to load as an ordinary key named `<<`, with the mapping under it hidden from every rule, so a rule on a key that mapping holds now sees a value it did not, a rule on the key `<<` itself no longer matches, and a document with `*m: abc` that used to load is now refused: `validate` reports it as a parse error naming the file and the position and exits 5, `test` fails the case that holds it, and through `run_checks` the refusal is the parse error a written `<<: abc` already earns (`ParseError`, FFI code 5, naming the file). A C or Lambda caller that branches on that code, or a rule that read the hidden mapping's keys as absent, sees the change. Example: over `Resources: { A: { &m <<: { Encrypted: true }, Name: a }, B: { *m: { Encrypted: true }, Name: b } }`, the `*m:` under `B` is a merge key, so `Resources.B.Encrypted == true` reads `true` where it read an absent key (the mapping sat under a key named `<<`).
* An alias of a plain scalar the reader keeps as text (an integer outside the signed 64-bit range, either sign, in any radix, or `.Inf`) is that scalar as a key, so beside its quoted spelling it is the same warned collision wherever the anchor was written; that pair's verdict and exit code do not move, only the warning. Example: with `hold: &big 9223372036854775808` written as a value before `outer` (an alias refers back to an anchor already read), `outer: { <<: { *big: a }, "9223372036854775808": explicit }` merges the alias in as the kept literal beside its quoted spelling and draws the collision warning, and the held `explicit` stands; the anchor written as the key of a mapping closed before `outer` reads the same (pinned by `loader_tests.rs:an_aliased_kept_literal_keeps_its_form_wherever_the_anchor_was_written (cases "anchor_as_a_value", "anchor_as_a_key_of_a_mapping_closed_earlier")`). The collision is a merged key's: the literal and its quoted spelling written as two explicit entries of one mapping are a key written twice, the duplicate-key warning of the entries above, not this one.
* Two keys of one mapping that share an anchor's position (`&k x: 1` beside `*k: 2`, or two `*k` keys) are a key written twice and get the duplicate-key warning under `validate` and under `test` for a case's `input`, one line per extra entry; they used to collapse into one entry in silence. The warning names the lines the key was written at, an alias at its own line, and ends by naming the value that stands: "The first value is the one evaluated." or "The last value is the one evaluated." when that value sits at one of the two lines named, and "The value written at L:4,C:3 is the one evaluated." when an alias wrote it at a third line, as for `&k x: 1`, `x: 2`, `*k: 3`, whose warning used to say the first value stood while the alias's `3` did.
* An alias that writes an anchored key again no longer moves the key behind the entries written between them: `&k x: 1`, `y: 2`, `*k: 3` keeps the keys in the order `x, y`, as the plain `x: 1`, `y: 2`, `x: 3` does, so a capture over the map and a `.*` enumeration read the entries in the author's order; the key moves only when a plain spelling of the name sits after it, where the value written last has to stand. The value written last stands, whichever spelling wrote it: for the pair alone that is what stood before, so the verdict does not move; where a plain spelling of the name sat between an anchored key and its alias (`&k x: 1`, `x: 2`, `*k: 3`), the plain spelling's value used to stand, and the last one written does now. Example: `Tags.*` over `&k x: 1`, `y: 2`, `*k: 3` enumerates `3` then `2`, where it enumerated `2` then `3`.
* `json_parse` refuses an embedded string whose member names differ as written but read as one key, such as `{1: "a", "1": "b"}`, and the clause that called it fails closed, with a message that names the property and the key. Every key becomes text on the way into the value model, so the second member used to replace the first and nothing said so.
* Through `run_checks`: data that holds no document (empty, or only comments) evaluates as a null document, as it did before; a key written twice keeps its last value, as under `validate`, and silently, since this entry point has no terminal for `validate`'s warning; and a document the reader cannot parse is reported as a parse error (`ParseError`, FFI code 5, with the file's name and the reader's message under one prefix) where it was a YAML error (`YamlError`, FFI code 2) before the two readers were made one. A C or Lambda caller that branches on that code sees the change.
* A warning on stderr from `validate`, `test` or `rulegen` is one printable line, whatever it quotes: a control character, a bidirectional control or a zero-width character in a key, a YAML tag, a test case's name, a file name or a quoted key in a rules file is written as its Rust escape (`\n`, `\u{1b}`, `\u{202e}`), so a key holding an ESC can no longer open a terminal escape sequence from the stream and one holding a bidi override can no longer reverse the rest of the line; a backslash in a key or a tag is written as `\\`, so two names that would print alike print apart; and a backslash in a file name, in the position a deprecation notice names, and in the path and reason a gate notice names an entry by is kept as written, so a Windows path reads in a warning as it reads on stdout and in the report, and one entry is spelled one way on one line. The one path written with its backslash doubled is the pointer a comparison record carries to the record that holds the right-hand markers' list (the record entry below), which has to map back to one path. Text that compares a warning's quoted names or paths byte for byte sees the change for a name that holds any of these.
* For code that uses cfn-guard as a library: the `test` command's parsed case, `TestSpec` (`cfn_guard::commands::test::TestSpec`), is built by the command from the spec file and no longer derives `Serialize` or `Deserialize`; its `input` is the YAML reader's own value rather than a serde value, and it cannot be named or constructed outside the crate.
* For code that uses cfn-guard as a library: `cfn_guard::Error` gains the variant `Unevaluatable(String)`, a clause that has no answer on the data it was given, and `cfn_guard::InternalError`, the payload of `Error::InternalError`, gains `EventRecordMismatch(String)`, a defect in the evaluator's own bookkeeping, and `UncheckedParserInvariant(String)`, an invariant the parser keeps that reached evaluation unchecked (a parameterized call with the wrong number of arguments, a binary clause with no right-hand side; reachable only from a rules file assembled without the parser), each of which stops the run. Neither enum is marked `#[non_exhaustive]`, so a `match` outside the crate that names every variant stops compiling until it has an arm for each new one, or a wildcard arm.
* For code that uses cfn-guard as a library: `cfn_guard::Error` also gains `MissingDocument`, data that parsed and held no document; `UndecidableComparison(String, Option<RefusalToken>)`, a comparison the engine abandoned part way, such as a regular expression that ran out of backtracking budget, its second field the refusal token: a count the evaluator mints where it registers a refusal or delivers one as a marker, carried on the marker a refusal leaves inside a filter predicate and on the error a clause raises over that marker or a block folds, which the predicate run reads against the count at its start to mark the entry it was deciding a refusal (`None` for a comparison abandoned for any other reason and for an error rebuilt from its text; a token minted while a file-level `let` was lazily resolved inside the run marks no entry, the binding running once for every reader, where a `let` owned by a block built inside the run, or by a called rule's body, is the run's own); `cfn_guard::RefusalToken` is opaque to consumers, a type with a private field and no public constructor that a `match` can name (`UndecidableComparison(_, Some(_))`) and can neither construct nor read (its `Debug` form is `RefusalToken(..)`, so printing an error shows no count either); the variant is new in 3.2, so the second field breaks no released `match`, and a consumer that names it writes `UndecidableComparison(reason, _)` for the text, or `UndecidableComparison(..)` where it reads neither field; the kind of an `Unevaluatable` (whether the engine raised it as a refusal) is not on the error at all but answered by the engine's own registry, so that released variant keeps its shape; and `UnsupportedDocument(String)`, a document that parsed and holds a construct cfn-guard does not model, which is also how valid JSON that the YAML reader refuses is reported. An exhaustive `match` on `Error` needs an arm for each of these too.
* For code that uses cfn-guard as a library: `parse_template_and_call_gen` (`cfn_guard::commands::rulegen::parse_template_and_call_gen`) returns `Result<RuleMap, cfn_guard::Error>`, where `RuleMap` (`cfn_guard::commands::rulegen::RuleMap`) names the resource type to property name to values map the function has always built; a template it cannot read comes back as a parse error, where the function used to write the message to stderr and exit the process. A caller that used the returned map directly now unwraps or propagates it.
* For code that uses cfn-guard as a library: the constant `INPUT_PARAMETERS` (`cfn_guard::commands::INPUT_PARAMETERS`) reads `("input-params", 'i')`, the flag `validate` has accepted all along, where it used to read `("input-parameters", 'i')`; a command line built from the constant now names the flag the parser recognizes, and the old spelling, `input-parameters`, is accepted as a hidden alias of `--input-params`, so a command line built from the old value still parses.
* For code that uses cfn-guard as a library: `TestExpectations` (`cfn_guard::commands::test::TestExpectations`) and `ValidateBuilder` (`cfn_guard::ValidateBuilder`) implement `Default`; both are additions, and nothing that compiled against them stops compiling.
* For code that calls cfn-guard through its WebAssembly entry point (`tryBuildAndExecute`, which rejects with a JavaScript `Error` whose message is the run's diagnostic): for a run that evaluated no rules file, or no data file, the message now opens with the warning that nothing was checked, and the lines naming the files the directory walk passed over follow it, at most twenty named and the rest counted; it used to open with the file names and end with the warning. A caller that matched on the message's first line sees the warning where it saw a file name. The command line's own stderr is unchanged and keeps the names first.
* For code that uses cfn-guard as a library: `Writer` (`cfn_guard::utils::writer::Writer`) gains no method that returns both of a run's streams at once. Code that needs stdout and stderr from one run writes each to a `WriteBuffer::File` and reads each file back through a `Writer` of its own, with `stripped` and `err_to_stripped`.
* A variable bound to another variable that names a top-level key, `let all = Resources` then `let r = %all`, is read as that key wherever `%r` is used: a filter or `.*` over it on a template with no such key, or an empty one, is an empty selection and the clause is not applicable, as it is for `let r = Resources` and for the key written out. `%r.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'b'` over `{}` or `{"Resources": {}}` used to fail at exit 19 through the alias while the direct spelling passed at exit 0 with nothing to check; both now exit 0, and so does a parameterized rule passed `%r`. A `!exists` or `empty` assertion over the same selection through the alias used to pass and is now not applicable. See [CLAUSES.md](docs/CLAUSES.md#filtering-through-a-variable).
* A filter written directly after a variable bound to a list below the top level, `let cs = spec.template.spec.containers` then `%cs[ name == 'app' ] exists`, over `containers: []` is not applicable, exit 0, as the literal `spec.template.spec.containers[ name == 'app' ] exists` is; through the variable it used to read the empty list as the authored `containers[*][ name == 'app' ] exists` does and fail at exit 19, and the authored spelling keeps that failure. The negated filter and a `when` gate over it move with it: `%cs[ name == 'app' ] !exists` used to pass over the empty list and a negated gate used to open its block; both are not applicable now, as the literal spellings are. A rule that demands a matching container therefore lets a pod with `containers: []` through at exit 0 when written through the variable, as it always did when written as the literal filter; write `%cs[*][ name == 'app' ] exists` to keep the failure on the empty list. The same holds through a let-chain, a parameterized rule's parameter and a list one level down. See [CLAUSES.md](docs/CLAUSES.md#filtering-through-a-variable).
* A key filter's function argument read from the scope beside the map (`Resources.Cfg.Map[ keys == to_lower(Wanted[ Use == true ].Name) ]` over a document whose `Wanted` sits at the top level, not in the map) is read as a value beside the map, so a bare `Wanted:` there (null) under the filter is the absent key's unresolved read and the clause fails closed at exit 19, naming `/Wanted`, as it does when the map's own `Wanted:` is bare; it used to read the top-level null as the document's empty population and report the rule not applicable at exit 0, with the root-read notice, where the same null in the map failed. The notice is still printed for the read from the top level. `Wanted: []` and an absent `Wanted` keep their readings (the empty set, not applicable; the in-map miss, failing closed). The same holds when the argument's first key names the document's own population: `Mappings.Allowed[ keys IN to_lower(Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName) ]` at the file's root over a bare `Resources:` fails closed at exit 19 (it used to read the null as the empty population and report the rule not applicable at exit 0 under `IN`, passing under `NOT IN`), while over `Resources: {}` it stays the empty set and the plain clause `Resources.*[ ... ].Properties.BucketName empty` keeps its population reading over both. See [CLAUSES.md](docs/CLAUSES.md) and [FUNCTIONS.md](docs/FUNCTIONS.md).
* `IN` and `NOT IN` against a bare filter capture (`Prefix IN %buckets` after `Resources[ buckets | Type == 'AWS::S3::Bucket' ]`, `'Bkt' IN %buckets`, `let lit = 'Bkt'` then `%lit IN %buckets`) compare the left operand with the keys the capture holds as with a written-out list, over one key as over two: `Prefix IN %buckets` holds when the prefix is one of the keys (`BktOne` over the keys `BktOne` and `BktTwo`) and not when it is a substring of one (`Bkt`, which held before this change), and `'a' NOT IN %x` over the one key `Fallback` holds (it failed before this change, when a capture of one key was searched as text). cfn-guard 3.2.1 reads a document value on the left the same way; it read a bare literal on the left as a key path and a `let`-bound literal against every key at once. A query rooted at a capture carries the enumeration too (`let lit = 'prod'` then `%lit IN %t.Value` after `Tags[ t | Key == 'Env' ]` is membership in the values, as the inline `Tags[ Key == 'Env' ].Value` reads). See the `IN` table in [docs/CLAUSES.md](docs/CLAUSES.md).
* A parameterized rule whose `when` condition declares a filter capture under one of its own parameter names, `rule check(p) when Resources[ p | Type exists ] !empty { %p[ Statement exists ] !empty }`, is refused when the rules file is loaded, with a message naming the parameter and the rule, and `validate` exits 5 as it does for any rules file it cannot parse; every `%p` in the rule read the parameter, so the capture could never be read, and the file used to load and evaluate with the capture doing nothing. See [CLAUSES.md](docs/CLAUSES.md#filtering-through-a-variable).
* A filter straight after `.*` over a map holding a bare key beside its members, `Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists` over a `Resources` whose `B:` has no body, hands the null entry to the predicate, which fails on it and drops it, so the members beside it decide the clause and it passes at exit 0; in the released 3.1.12, 3.2.0 and 3.2.1 binaries, built from the release commits and measured, it failed: the rule reads `FAIL`, and the released CloudFormation reporter then panics at exit 101 (`internal error: entered unreachable code`) in place of a failure text; the retrieval error `Filter on value type that was not a struct or array null /Resources/1` was read on 3.2.1's type-block line over the list twin of this template. The cells, this spelling's and the absence check's, are tabled under the one-object `[*]` rule in [docs/CLAUSES.md](docs/CLAUSES.md#one-object-wildcard).
* A filter straight after `[*]` over a map of members, `Resources[*][ Type == 'AWS::S3::Bucket' ]` over a `Resources` map, enumerates the resources and selects the buckets, as `.*` and the literal `Resources[ ... ]` do; the released 3.1.12, 3.2.0 and 3.2.1 binaries, built from the release commits and measured, asked the filter's predicate of the document that holds the `Resources` map, which has no `Type`, so they selected nothing and `Resources[*][ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists` was not applicable at exit 0 with a bucket unflagged (`Resources[*][ Type == 'AWS::S3::Bucket' ] empty` passed and `!empty` failed). The cells are tabled under the one-object `[*]` rule in [docs/CLAUSES.md](docs/CLAUSES.md#one-object-wildcard).
* A filter straight after `[*]` over a list, `Resources.*.Properties.Tags[*][ Key == 'Env' ].Value == 'prod'` over list-shaped tags or `Resources.*.Properties.PolicyDocument.Statement[*][ Effect == 'Allow' Action == '*' ] empty` over a one-element `Statement` list, enumerates the list's elements and evaluates the clause over them. The cells are tabled under the one-object `[*]` rule in [docs/CLAUSES.md](docs/CLAUSES.md#one-object-wildcard).
* A filter straight after `.*` over a list, `Resources.*[ Type == 'AWS::S3::Bucket' ] !empty` or `Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName exists` over a `Resources` written as a list of buckets, and `Resources.*.Properties.PolicyDocument.Statement.*[ Effect == 'Allow' Action == '*' ] empty` over a one-element `Statement` list, enumerates the list's elements as `.*` over a map enumerates its entries. The cells are tabled under the one-object `[*]` rule in [docs/CLAUSES.md](docs/CLAUSES.md#one-object-wildcard).
* The reason a report carries for a key filter (`[ keys == ... ]`) whose right-hand side stopped at a value that is not a map, or whose right-hand function had no answer for a value or refused one (`parse_int` over a string it cannot read, whose message names the value), quotes that value cut at 256 printed characters with a marker naming how many were left out, its line-breaking, control and bidirectional characters written as their Rust escapes and the backslash kept as written, in every output that prints the reason (the per-value records, the `-o json` and `yaml` `error_message`, the refused-read line); a value under the bound with none of those characters reads as before, and a refusal's own sentence embedded in such a reason is never cut. The reason that leads a record for a value the document lacks beside a marker of either kind (a refused read's or a key filter's, on either side of the comparison) keeps its backslash as written the same way (unmeasured on the releases: no fixture row holds a key filter over a long value, so the baseline is this evaluator's reading before the change). See the behavior-change entry on the key filter's quoted text in [docs/CLAUSES.md](docs/CLAUSES.md).
* The reason a report carries for a key filter (`[ keys == ... ]`) that met a value with no entries to select among reads `Map Filter for keys was not a struct <type> <path>` whichever part sat before the filter, the key itself, `.*` or `[*]`; after a wildcard it used to read `Filter on value type that was not a struct or array <type> <path>`, the wording for a filter over properties. A consumer that matched the old string for a key filter after a wildcard sees the new one. Two verdicts move with the same change: `%r.B.Properties.Tags[ Key == 'Env' ] exists` with `let r = Resources` over a template with no `Resources` key was not applicable and now fails at exit 19 on the key `B`, as the spelling without the alias does; and `X[*].K[ ... ] exists`, a wildcard then a key then a filter, over a bare top-level `X:` (null in YAML) or over `X: {}`, used to fail on the key and is now not applicable, as it is over `{}` and over `X: []`. The other polarity moves with it: `X[*].K[ ... ] !exists` over the same two used to pass, reading the key as absent, and is now not applicable, so a `when` gate written on it that used to open its block leaves it unopened and the assertions in the block are not run; and the block spelling `X { this[*].K[ ... ] exists }` moves as the plain one does, from failing on the key to not applicable.
* A key filter whose right-hand side is itself refused on the data, `Resources.*.Properties.M[ keys == Tags[ Key == 'Env' ].Value ]` over a map `M` whose own `Tags` holds a string (a bare right-hand query reads the map being filtered alone, so a `Tags` beside `M` is a key `M` lacks, an absence and no refusal) or `[ keys == to_upper(Tags[ Key == 'Env' ].Value) ]` over a resource whose `Tags` holds a string (a function argument falls back to the resource beside the map), is answered for that map as a key filter whose right-hand side the document lacks is: the map is recorded as undecidable with the refusal as its reason, and the clause reads it as it reads every undecidable map. A rule over the one refused map fails closed in either polarity, as it did when the refusal was an error, and the failure is now recorded at the map; under `some` over several maps a sibling whose own selection passes settles the clause, so `some Resources.*.Properties.M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] !empty` passes over a list-tagged resource beside the string-tagged one where it used to fail at exit 19 with the line "Clause could not be evaluated against the incoming context ... when handling clause, bailing"; and a `when` gate over several maps whose operator is a comparison is settled by a sibling, so `when Resources.*.Properties.M[ keys == Tags[ Key == 'Env' ].Value ] == 1 { ... }` reads not applicable at exit 0 when another resource's selected value is a decided failure, and `when some Resources.*.Properties.M[ keys == to_upper(Tags[ Key == 'Env' ].Value) ] == 1 { ... }` opens its block when another resource's selected value passes, where both used to fail the rule closed; a gate whose operator is `exists`, `!exists`, `empty` or `!empty` fails the rule closed on the undecidable map whatever the siblings say, as it did. A capture on the filter (`[ n | keys == ... ]`) holds the marker, so `%n exists` fails closed with the reason where it used to read an empty binding.
* A filter over a section's entries, under every spelling (`Resources[ Properties.Tags !exists ] empty`, the same through `let r = Resources` and `%r[ ... ]`, after `[*]`, after `.*`, and the block's `this[ ... ]`), passes an entry under an intrinsic directive key over when the predicate is about the members, by the entry's own key and position and never by the kind of what sits beside it: any `Fn::` key at a template section (`Fn::Transform`, an `AWS::Include`, beside the resources or alone; a map-valued `Fn::ImportValue` written where a member would be), and `Fn::ForEach::<Name>` (an `AWS::LanguageExtensions` loop) at any depth, alone or beside members, since a loop writes keys into the map that holds it and its expansion, not the loop, is the members. The section rule, the `Parameters` exception and the cells are under [item 15 of docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md#filter-after-a-wildcard-over-a-map-holding-the-key).
* A query a report renders with the parser's own name for a filter (a `Check =` or `Context=` line, a remaining query, an empty-selection reason) joins an unnamed filter without a `.`: `Resources.* (filter-clauses)`, `Resources (map-key-filter-clauses).Type`, `Resources.B.Properties.Tags (filter-clauses)`, where the same texts used to read `Resources.*. (filter-clauses)`, `Resources. (map-key-filter-clauses).Type` and `Resources.B.Properties.Tags. (filter-clauses)` with a stray `. `. A named filter keeps its `.` (`Tags.p (filter-clauses)`), a quoted key keeps its `.` whatever its text (`M.[x` for the key `"[x"`, where it used to render `M[x`), and a numbered index keeps its `.` as before (`Tags.0.Key`).
* A key filter over a map with a scalar entry whose predicate can hold by absence is refused only where reading the map as one object disagrees with the walk over its entries, and that reading now reads the predicate as `X[*][ ... ]` reads it: a function argument the map lacks is read from the scope beside the map, so `Cfg[ Owner !exists  this[ keys == to_upper(Env) ] !empty ] empty` over `Cfg: { Mode: fast, PROD: 1 }` with `Env: prod` at the document root is refused at exit 19 with the `X[*][ ... ]` remedy (it passed at exit 0, the readings disagreeing unseen) and passes at exit 0 over `Env: dev`, as `Cfg[*][ ... ] empty` passes there; an error the reading meets is the filter's own, so `Cfg[ Owner !exists  this[ Owner !exists ] !empty ] empty` over that map fails at exit 19 with the nested refusal the `[*]` spelling raises (it passed at exit 0), while a failing conjunct beside the refused clause (`Kind == 'k'` over a map without `Kind`) still passes `empty` under both spellings, and a rules-file mistake inside the predicate (`parse_int('abc')`) exits 5 under both where the key spelling used to pass at exit 0 beside such a conjunct. See [docs/CLAUSES.md](docs/CLAUSES.md#filtering-through-a-variable); the cells are tabled under [item 15 of docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md#filter-after-a-wildcard-over-a-map-holding-the-key).
* `Resources[*].<id>.Key`, `%r[*].<id>.Key`, and `%r.<id>.Key` or `%p.<id>.Key` after `let r = Resources[*]` or `check(Resources[*])` (the key read after a binding of the wildcard: the Kubernetes `let res = Properties.resources[*]` then `%res.limits exists` is refused as `resources[*].limits exists` is, the remedy naming the source `Properties.resources` as `X`, never the bare `%res`) over a map of members sharing key names (`Resources[*].A.S == "abc"` over `Resources: { A: { Type, S }, B: { Type, S } }`) read the resource `A` and passed; they are refused (FAIL in both polarities), the remedy the direct path `Resources.A.S`. The same rule for the block and key spellings after `[*]` over a map whose own key names a member: `Resources[*] { Type exists }` and `Resources[*].Type` over a `Resources` map of two or more resources sharing a key name are refused whether or not every member carries a `Type` of its own: `[*]` hands a map on whole, so both were answered by the map's OWN entry named `Type` for every member, a pass over `Resources: { Type: { Name: x }, B: { Type: .., Name: y } }` though the member `Type` holds none of its own, and a read of the member named `Type` where every member carries one (a called rule's `when Type == 'T' { Name exists }` over such a map skipped its body on the map's own `Type` while a member lacked `Name`, at exit 0); the refusal names the direct path (`Resources.Type`, the map as one object) and the member spellings (`Resources.*.Type`, `Resources.* { Type exists }`). On a compliant template the move is a container's `resources` gaining a `requests` entry beside `limits`: with `limits` alone the map is one object and `resources[*].limits exists` reads it; with both, two members share `cpu` and `memory`, the map is a candidate collection, and the same clause is refused with the remedy `resources.limits exists`. The Kubernetes `resources: { limits: { cpu, memory }, requests: { cpu, memory } }` is that shape: `resources[*].limits exists` passed on the map's own `limits` and is refused, the remedy `resources.limits exists`. A `Properties` of nothing but sub-maps that share a key is the block spelling's instance of it: `Properties[*] { VersioningConfiguration.Status == 'Enabled' }` over `Properties: { VersioningConfiguration: { Status: Enabled }, LoggingConfiguration: { Status: Enabled } }` passed on the map's own `VersioningConfiguration` and is refused, FAIL at exit 19, the remedy `Properties.VersioningConfiguration.Status == 'Enabled'`. The keys the block reads are read through its own `let` bindings, its `when` conditions and bodies, and the bodies that run over the same value (`this`, a binding of `this`, a rule called with `this`, that rule's own `when` condition among them), so none of those spellings answers from the map's own entry. A map with a scalar or an intrinsic-call entry, of one member, or of sub-maps sharing no key name is one object and reads as before. The block's refusal is per value: the refused map gets its own failing record and the block's other values are evaluated, so `some` is settled by a passing sibling; inside a filter predicate or a `when` gate it is the block's undecided value, so the filter is refused in both polarities and the gate fails its rule closed, the refusal printed whole. A nested block over the bare `this` (`Resources[*] { this { Type exists } }`), a key read through the block's own `let` binding (`Resources[*] { let t = Type  %t exists }`), a `when` block's body and the two aliases of `this` (`let v = this` then `%v { .. }`; `check(this)`), and a block over a binding or a parameter bound to `Resources[*]` (`let r = Resources[*]` then `%r { Type exists }`; `rule check(p) { %p { Type exists } }` called as `check(Resources[*])`) are refused the same way. The cells are tabled under [docs/CLAUSES.md](docs/CLAUSES.md)'s behavior-change callout of the same name.
* A filter straight after `.*` over a map holding a scalar entry, under a predicate that holds on the map itself by the absence of a key, reads the members and is not refused for the scalar: `spec.*[ securityContext !exists ] !empty` over a `spec` whose `replicas: 3` sits beside two sub-maps lacking the key keeps the sub-maps and passes, and over a `spec` of nothing but scalars selects nothing, so `empty` passes, `!empty` fails and a `when` gate on the selection stays closed, where the released 3.1.12, 3.2.0 and 3.2.1 binaries, built from the release commits and measured, failed on the scalar with a retrieval error in both shapes. The cells, the literal `spec[ securityContext !exists ]` among them, are tabled under [item 15 of docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md#filter-after-a-wildcard-over-a-map-holding-the-key).
* Where one raise folds several refused reads (two maps the `[*]` reading refuses under one block, a comparison whose right-hand side holds two refusals' markers, two refused clauses of one filter predicate), the reason the failing record, the `when` gate and the console carry is the refusal minted LAST, the map met last in document order; a comparison's raise still names every refused read it met, numbered with the read it kept, the later mint, first and the others after it in the order the comparison collected them (the right-hand reads in value order, then the left-hand ones), and no verdict moves with the wording. A refusal minted inside a filter predicate's run marks the entry as refused whichever order the run met its values in, so a capture bound outside the predicate that holds an older refusal no longer hides one minted inside it (the entry read as a plain undecided value, which the record reported as a spent budget; where the selection is the left-hand operand of the outer comparison the verdict of a `some` is unchanged, since a member that passes decides it, and where it is the right-hand operand a clause that no resolved right-hand value settles fails closed, as the bullet on a comparison whose right-hand side holds an undecidable marker says). See the behavior-change callout on the block and key spellings after `[*]` in [docs/CLAUSES.md](docs/CLAUSES.md).
* A comparison's raise inside a filter predicate carries the token the predicate's run owns when the registrations recover one for the refusal it met, and not the token a marker brought from outside the run: where a marker memoized by a file-level `let` carries an older token for a sentence the predicate's own body also raised, the entry is marked refused. The predicate's own verdict does not move; the record's flag and the refusal's report do. A selection that is the right-hand operand of an outer comparison still fails that clause closed when no resolved value in it settles the clause (see the bullet on a comparison whose right-hand side holds an undecidable marker, below).
* A rule that fails and whose failing block clause has per-value records that report nothing (the record a refused one-object selection leaves when the block exits before its fold carries no message in the assertion role; in a gate it carries the refusal's sentence, bare, which the failed condition's walk names once in the rule's sentence) is listed in the structured reports and the console by the block's own record, with its message where it has one (a block that raised a refusal as its undecided reason carries the refusal's sentence and is flagged a refusal) and otherwise the sentence "the block clause failed, and none of the checks recorded under it reports why", which is flagged as no refusal. A parent that has a message of its own (a `when` condition, a type block, a disjunction or an enclosing block) is listed by that message where nothing else beneath it reports, and its silent child blocks are not listed beside it; a parent with no message lists every silent child, including a silent failing block beside a sibling that reports. Where blocks nest and the innermost reports nothing, the generic line carries the innermost block's context. A rule whose `when` condition failed closed keeps the condition's sentence as the rule's own message and lists no checks beneath it, and when the condition met further refusals (a `when` of several disjuncts that each refuse) the rule's message names each of them once after the first (`; the condition also met: ..`; for a call that carries a `<< >>` body the list joins the rule's `error_message` and the `message` stays the author's body, which the console's `Error =` line and the structured reports read; the refusals of the called rule's body clauses that no check names follow, after the condition's, behind `; a body clause also met: ` (the condition did not meet them), and the head follows the record: a rule whose body or own condition ended on an error reads "The rule failed on an error that ended its evaluation" whatever the refusals it gained, and one that failed without an error says only that the rule failed; in `-o json` the refusal is then in `messages.error_message` and not in `checks`); the condition's records are walked only for a failed rule that has no message of its own, and a type block's failed condition is walked the same way. A silent block that nests in a block over many values is listed once, not once per value. Before this change `-o json` listed the rule with empty `checks` and null messages for a run that had exited with the failure code.
* A filter predicate whose own body raised a refusal and that then reads a file-level `let` whose query raises the same sentence (first read inside the run, or met afterwards by a comparison over it) keeps the entry marked refused, so the refusal is reported as one; the verdict of a `some` over a selection that is the left-hand operand of the outer comparison is decided by a member that passes, and a refused member is an undecided read the record and the refused-read line report (unmeasured on the releases: no release row holds this shape), while a selection that is the right-hand operand fails the clause closed when no resolved value in it settles the clause (see the bullet on a comparison whose right-hand side holds an undecidable marker, below). The token a comparison's raise carries is chosen the same way at every comparison raise, inside a filter predicate run or not, in the assertion role and in a `when` gate or a predicate alike: the marker's own token and the one the registry holds for the refusals the comparison met are folded by one rule under the run's ranking, so a token minted inside a binding resolution never displaces one the run owns. Outside a predicate run there is no run to own a token, so a raise that carried none now carries the registry's; that can change how the raise ranks against an error held beside it and whether its record is flagged a refusal, and the verdict does not change. A filter predicate opened inside the `let`'s own query does not change that: one sentence may carry several live tokens, the enclosing run keeps reading its own, and the nested run reads the token its own raise carries, so its entry is refused as well; a nested run that raises nothing afresh and meets the sentence only through the older token reads its entry plain (see [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md#a-binding-read-late-in-a-predicate-run-no-longer-turns-its-entry-plain)).
* A negated comparison under `some` whose right-hand selection holds an entry a filter predicate left undecided over two refusals of different age, an OLDER one minted before that predicate's run and read inside it through a capture and a NEWER one minted inside the run (`some Expected != Sub[ s | Members.* { Limits[*].K exists  %c exists } ].Name`, with `%c` bound to a refused read outside `Sub`'s predicate and one member's `Limits` refused inside it), is raised on the refusal minted inside the predicate's run, the newer one, whose pair the fold keeps over the older capture's: the undecided entry is marked refused by it, and so is the enclosing entry whose run minted it: FAIL at the validation failure code, where it passed on the resolved `Expected` beside the undecided entry. The undecided entry's marker carries the refusal's token through the comparison, so the refusal decides the clause it stands in and is never silent; where the run meets the older refusal alone, the entry stays plain and carries the token on to the run that minted it, which is marked by it.
* A refusal's text quotes a template key or path the same way wherever it is written, the console and the `-o json`, `yaml`, `sarif` and `junit` reports alike: as the warning line prints a key (a control character, a bidirectional control or a zero-width character as its Rust escape, `\n` or `\u{1b}`; a backslash in a key as `\\`, in a path as written), each template-derived part cut to a bound, where the cut shortens it, with a marker naming how many characters were left out (a key at its end, a path in its middle so the leaf segment and its location stay; a part a few characters over the bound prints whole, since the marker would make it longer). One exception to "a backslash in a path as written": the path a comparison record's pointer names (the record that holds the right-hand markers' list, below) is written one-to-one, its backslash doubled, so a logical id holding a tab and one holding the two characters `\` `t` point at different records. A consumer that compared a structured report's refusal text with a raw key sees the escaped form.
* A comparison whose right-hand side holds an undecidable marker (a refused `%name`'s, or the one a key filter leaves for a map whose keys it could not read) beside resolved values or absent operands is read pair by pair, and only a clause nothing else decides fails closed on the marker. A comparison whose right-hand values are all undecided markers, with no refused read among the values, fails closed, under a rule's assertion (a `when` gate raises on one reason), on every marker's reason, and a `not` over its rule fails closed with them: the record names the first four reasons and counts the rest once. The same holds for a strict `some .. NOT IN` over several such markers, where the fail-closed `not` before this change named one reason and counted none. The moves are the bullets that follow; each is listed with the test that pins it under the behavior-change entry for this comparison in [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* Membership settled by a listed value beside a marker: `when Y IN <selection with a marker>` with `Y` equal to a resolved value runs its body, where this evaluator before the change failed the rule (unmeasured on the releases: no fixture row holds this shape), and the assertion `Y IN <selection with a marker>` passes the same way; with `Y` equal to no resolved value the rule still fails closed, since the unread map may hold `Y`. A refused read beside the listed value is reported on stderr rather than raised, and the passing clause carries no failing child record (a non-failing record of the refusal there is a later change), where a reference the document lacks beside the same listed value still fails the membership: the two readings stand as this evaluator read them before the change (no fixture row holds the shape). Example: with `%x` captured as in the fixture `captured_modes_beside_a_refused_walk.yaml` under `guard/resources/validate/wildcard-filter-release-verdicts/` (the keys `Fallback`, `A` and `B` beside the marker of a refused walk), `when Names[0] IN %x { ... }` with `Names: [A]` runs its body: `A` is a listed value, so the unread entry decides nothing. See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* `some X NOT IN %x` and `some X != %x` beside a marker of either kind (a refused read's, or a key filter's), `X` equal to no resolved value, fail where this evaluator before the change passed (unmeasured on the releases: no fixture row holds a non-matching value beside a refused read's marker; beside a key filter's marker the releases left no marker, since a key whose regular expression spent the engine's limit ended the whole `validate` run: the engine's error escaped the rules-file evaluation before any report was written, and the run exited 255 with `Error occurred <the regex error>` on stderr and no report for the data file (by a static read of the 3.2.1 sources, unmeasured against a built release; the same read shows the key filter resolved its right-hand side before any key was matched), so a release never reached this comparison), because the pass a value reads beside the marker may be against the very value the marker hides; a resolved match under the negated comparator stays a decided no. Example: with `%x` captured as in the fixture `captured_modes_beside_a_refused_walk.yaml` (the keys `Fallback`, `A` and `B` beside the marker of a refused walk) and `Names: [Z]`, a name equal to no key, the assertion `some Names[*] NOT IN %x` fails at the validation failure code, where it passed on `Z` beside the marker before this change (the release fixture row for that gate holds every name colliding, not `Z`); with `Names: [A]`, a name equal to a key, the clause is a decided no in both. See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* `when L[*] == <selection with a marker>` with a left-only mismatch (`L: [x, z]` against the resolved `x` and the marker) fails closed, where this evaluator before the change reported the rule not applicable (unmeasured on the releases: no fixture row holds this shape), because the unread map may hold `z`; a right-only mismatch (`[x]` against `x`, `w` and the marker) stays a decided no and the rule not applicable. See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* An absent operand beside a marker of either kind (a value the document lacks, an empty collection, a right-hand reference that resolved to nothing) is a decided failure for that value, so a `when` condition is not applicable and a filter predicate deselects the entry (one exception, read the same way by the comparison's collections and by a key filter: an absence whose own reason the registry holds as a refusal is a refused read by that text, not a decided failure; the classifier keeps that reading although no producer leaves such an absence now, a filter over a scalar inside a predicate delivering the refusal's own marker instead; pinned by `eval_tests.rs:a_marker_of_any_kind_is_a_refused_read_by_one_reading_on_both_sides`), where this evaluator before the change failed the rule closed in both roles (unmeasured on the releases: no fixture row holds an absent operand beside a refused read's marker; beside a key filter's marker the releases left no marker, since a key whose regular expression spent the engine's limit ended the whole `validate` run at exit 255 with `Error occurred <the regex error>` on stderr and no report for the data file (by a static read of the 3.2.1 sources, unmeasured against a built release; the same read shows the key filter resolved its right-hand side before any key was matched; whether a release ran the key filter at all over an empty left-hand selection is not read here), so a release never reached this comparison); a refused read beside such a decision is reported on stderr and in the absent value's own record, after the retrieval's own reason and printed whole by the console (as is the refused read beside a value no listed entry accepted under a positive `IN`), rather than raised. Two shapes keep the reading this evaluator gave before the change (no fixture row holds them): a right-hand reference the document lacks under a positive `IN` beside a marker is a decided no for its own pair alone, because membership is `OR` over the pairs, so `when Owner IN %names` with such a reference and a marker among the values, `Owner` equal to no listed value, is raised on the marker's reason, as this evaluator read it before the change; and under `some` a right-hand reference that resolved to nothing beside a marker, with no resolved value beside them, is raised in both polarities rather than decided, since the marker's pair may be the one the value passes against, where the `match_all` spelling is decided by the absence. Example: `Resources.*[ Properties.Size IN %limits ].Type == 'X'` with an undecidable entry in `%limits` deselects a resource with no `Size` where this evaluator before the change failed the rule (no release row holds the shape; the decision is pinned under `==`, `!=`, `IN` and `NOT IN`, not under an ordering). See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* An empty left-hand selection beside a refused read's marker (a `when` condition or a filter predicate whose left-hand query selected nothing, compared against a selection that holds a refused `%name`'s marker) is raised and fails the rule closed at the validation failure code, because nothing it compared could stand in for the refused read; this evaluator before the change reported it as the empty selection at exit 0 with the refusal registered and nothing written for it, and the released binaries stopped with an internal error on the one map-shaped-tags document the fixture row in [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values) names (their two refused-walk gate rows read not applicable at exit 0); no release row measures the empty selection itself. Beside a key filter's marker alone (a map whose keys a regex out of budget could not read, no refused read among the values) the same empty selection keeps the answer this evaluator gave before the change (unmeasured on the releases: no fixture row holds the shape) under every comparator: the condition is not applicable and the predicate deselects the entry, with nothing written, since the operators answer not applicable for nothing on the left before any comparator is read (pinned by `an_empty_left_selection_beside_a_key_filters_marker_keeps_its_answer`; the `NOT IN` gate and predicate are the pinned spellings, and the other comparators, which take the same arm, are unpinned). Example: `Resources.*[ Type == 'AWS::S3::Bucket' ][ Properties.Tags[ Key == 'Owner' ].Value == %names ] empty` with `%names` refused over a map-shaped tag set and no resource holding such a tag is raised (exit 19), where `when Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Owner NOT IN %names { ... }` over a template with no bucket, `%names` holding a key filter's marker alone, leaves its body unopened and the rule not applicable. See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* A refused read beside a value that does NOT match (`[ Properties.Owner == %names ]` over an `Owner` no listed pair equals, `when Cfg.Mode == %x` with a resolved mismatch, `when some Names[*] NOT IN %x` with every name colliding) lets the resolved no decide, so the predicate deselects the entry and the condition is not applicable. The released 3.1.12, 3.2.0 and 3.2.1 binaries, built from the release commits and measured, read the two `when` conditions not applicable at exit 0 (the rows record SKIP, and nothing about what the releases wrote of the refused read), and stopped on the filter predicate with an internal error, `entered unreachable code`, before any verdict; the three fixture rows that measured it are named in the behavior-change entry in [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* The refused-read line: a refused read a comparison was decided without raising (beside a value that does not match, beside a decided absence, beside the listed value that settled a membership, or beside a `some` that passed on another of its values) is registered and reported on stderr once per clause site, as one `Warning:` line naming the clause as the evaluator renders it (membership operators lowercase; a `when` block, a rule's own `when` and a type block's `when` by their conditions as the grammar spells them, the disjuncts of one conjunction joined by ` or ` and the conjunctions by ONE space, `when a or b c`; a type block by its name with that `when` text where it has one; a reference or a call in a rule body whose rule failed at its own leaf on a refusal writes the line at the REFERENCED rule's clause, `%p exists` or `Resources.*.Cfg[*].Limits exists` as written, one line however many references judge that leaf FAIL (pinned by `eval_tests.rs:a_body_level_call_decided_past_is_named_at_the_referenced_rules_clause (cases "C", "R")`; the one-space rendering of a `when` or type-block head by `eval_tests.rs:a_when_or_type_block_head_renders_its_conditions_with_one_space_between_conjunctions (cases "W2", "TW", "T")`); a call whose argument refuses at the call site itself, before the called rule's body runs, is named by the call's own text, a rendering no cell pins and this document leaves undocumented), how it was decided (with the count of evaluations each way when it was decided more than one way), the distinct refusals (numbered when there are several), and ending with the clause's position and the input it was found in (the data file under `validate`, the case and its spec file under `test`); this evaluator before the change wrote no such line (the rows record SKIP on the releases and nothing about what they wrote).
* A reference's `not` over a rule that failed decides one of two ways by the STRUCTURE of the rule's body, not by a count of what it noted, and writes the line in one of them: a rule whose FAIL is a decided no (a conjunct that answered no beside the refused comparison, since `AND(no, unknown)` is `no`; every branch of a disjunction or of a `some` block decided) is inverted to a pass as before, the refused read's line reading "passed by the negation of a rule that failed"; a rule whose FAIL rests on reads it could not decide (`rule main { not check }` with `check` failing only on `some %y NOT IN %m` over a refused `%m`; `rule check { A or B }` with `A` a decided no and `B` the refused comparison, since `OR(no, unknown)` is unknown; a `some` block one of whose entries failed on a refusal) FAILS the `not` closed, where this evaluator before the change passed it, a verdict the refusal manufactured (no release row holds the shape). The fail-closed `not` writes no refused-read line: failing closed is acting on the refusal, so its own FAIL record carries the refusal instead ("the negated rule [check] failed only on reads it could not decide, so the negation fails closed rather than passing: <the refused read>"), naming at most four of the reads (or, where the undecidable is no refusal, four of its causes) and counting the rest once ("; 3 more refused reads not named", "; 1 more refused read not named"), with the author's `<< >>` message on the reference in the record's own field, as every block-shaped record of a clause that carries one now has it (a clause decided over an empty selection, a clause whose query or comparison raised, a call whose argument could not be evaluated; the console summary and `-o json` print it once, where this evaluator before the change dropped it from those records); as a `when` condition the negated rule runs in the gate role, where every undecidable leaves it as a raise that reaches the reference before any negation, so the rule it gates fails closed on its condition rather than opening or skipping (pinned by `eval_tests.rs:a_negated_reference_decides_by_the_structure_of_the_rules_folds (cases "A1", "O1", "S1", "G1", "D1")`).
* One exception to the conjunction rule, decided by one test in every role: a block whose body read the empty selection a one-object filter left, and was refused there, has a body whose decided no holds under the reading of the filter that kept an element and not under the reading that kept none, so the block's FAIL is decided exactly when its judgement over its other values alone equals its judgement over them plus that failure, the status and the basis of a FAIL alike, and rests on the refused read otherwise. Alone, the readings agree only under `not empty` (without it the other reading is SKIP, so `not` over the rule fails closed, where this evaluator before the change inverted the body's no into a PASS: `not check` PASS at exit 0 before the change, FAIL at the validation failure code now); beside sibling values a `some` block agrees unless every sibling skips (`not check` passes with the read's line where the siblings fail), an every-entry block agrees where a sibling fails on a decided no and disagrees where every sibling passes or where every failure rests on an undecidable (there `not check` fails closed naming every read, and as a `when` condition the block raises and the rule it gates fails closed, where this evaluator before the change reported it not applicable at exit 0 with its assertions unchecked); a sibling the block could not decide (a raise it holds, another refused selection whose body is undecidable) agrees with nothing, so the block raises unless another sibling decides it (a sibling that fails on a decided no decides an every-entry block); a refused selection with no value beside it is judged after every selection has run, as a lone selection is: beside a second refused selection whose body is undecidable the siblings are undecided, so `not check` fails closed and the gate fails closed in either map order. A selection is refused by a read of a key the object LACKS; a key the object HOLDS (`Effect` over a one-object statement) is read as nothing over the refused selection, as the dotted spelling `Statement[*][ Principal == '*' ].Effect == 'Deny'` reads it, so a clause on it is not applicable and a `when` in the body gated on it reads nothing and leaves the value not applicable, never refused (the "GKk"/"GKek" rows); the chained-filter spelling `[ Sid exists  Effect == 'Deny' ] !empty` is refused only when every key it names is lacking (the second-filter rule in [docs/CLAUSES.md](docs/CLAUSES.md)), so naming the held `Effect` it is not refused and keeps nothing, the empty selection its list twin is, and its `!empty` fails where the block fails closed (the "E1nk"/"E1i" pair). Beside a selection whose closed `when` read nothing a refused selection is judged as a lone one, and the one body a `when` can refuse over a one-object statement is gated on a key the statement lacks, an undecidable body: `not check` fails closed naming the read and the gate fails closed on its condition, in either map order (the "GKr2w"/"GKr2rw" pair; the selection the `when` closed on is not applicable, never refused). Siblings that every one skip are values the block has, so without the refused value the block is SKIP under `not empty` as well and the assertion role fails `not check` closed there, where as a `when` condition FAIL against SKIP counts as agreement, since both mean the guard did not hold (alone without `not empty`, the "E1d" row: the rule it gates is then not applicable); the every-sibling-skips arm of that agreement is reached by no row and stays unpinned: over a one-object statement a `when` that closes on the sibling closes on the refused selection's held key too, a comparison gate (the "GKk" row) and the unary `Effect !exists` gate alike (the "GKuk" row), or refuses its lacking one, so that value is not applicable or undecidable and never a decided no beside skipping siblings. The block's record is flagged a refusal by the block's own read, whatever the body decided beside it; beside siblings the refused value leaves a flagged per-value FAIL record under the block in either role (the gate's carries no sentence); the block's refused read is written "passed by the negation of a rule that failed" where that `not` passes, "was decided by a sibling clause's failure" where a `when` condition's block decided it by the body's no, and "was decided by a sibling entry's failure" where an every-entry block as a `when` condition decided past the undecidable value by a failing sibling, one line carrying both runs' verdicts where a rule runs in both roles (pinned by `eval_tests.rs:a_blocks_refused_read_over_the_empty_selection_is_judged_with_its_bodys_basis (cases "E1w", "E1d", "E1nk", "E1i", "E1io", "E2", "V1", "SP", "SF", "GS", "GSf", "GSsw", "GSsfd", "GKk", "GKuk", "GKsk", "GKnk", "GKsnk", "GSu", "GSr", "GKr", "GKx", "GKd", "GKr2w", "GKr2rw", "GKek", "GKenk", "SS", "GSs", "D")` and `eval_tests.rs:a_gate_role_block_over_a_refused_selection_beside_a_sibling_raises_or_writes_its_own_line_once (cases "GU", "GUd", "GUf", "GD", "MF", "MO")`). The every-entry agreement and disagreement beside a body whose no comes from a binding, and the line the two-selection shape writes, are pinned by the first test's cases "GSfd", "GSpd", "GKr2d" and "GKr2rd".
* The clause part of a refused-read line written for a block, a `when` block or a type block that failed on its own read now names the clause as the author wrote it (the block's text, `when <conditions>`, `AWS::SQS::Queue when <conditions>`) rather than an internal record key. Example: `when Cfg.Mode == %x` decided by a resolved mismatch beside a refused `%x` draws one line for the clause, however many resources the run evaluates. See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values) and [How `validate` writes notices](docs/CLAUSES.md#notices).
* An assertion raised on a refusal's reason (`some X NOT IN %x` beside the marker, `X IN %x` against the marker alone, `some %x NOT IN %y` with a refused walk's marker in each capture) is recorded as the refusal it is whichever side of the comparison the refused read stood on, printed whole by the console where every other recorded message is held to 320 characters (a bound of this evaluator, not of the releases), with the record sentence `Error <reason> when handling clause; the clause is raised and the run continues` where this evaluator before the change read `..., bailing` over a run that went on (unmeasured on the releases: no fixture row holds an assertion raised on a refusal's reason). Example: `Resources.B.Properties.Owner IN %names` with the marker alone in `%names` prints the refusal's whole sentence in its console record. See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* A refused read on the LEFT of a comparison against a plain right-hand side (a literal or a resolved value: `%x != 'zzz'` with the keys and a refused walk's marker in the capture `%x`) is recorded as the refusal it is, `refusal: true`, so the `-o json` and `-o yaml` `error_message` and the verbose console line read `Check was not compliant as the value to compare from could not be read. Error = [<the refusal's text>]` where they read `Check was not compliant as property [] to compare from is missing. Value traversed to [...]`, and the console prints the refusal whole; a consumer that matched the old sentence sees the new one. A left-hand value the document lacks with no refusal behind it keeps the sentence the releases wrote (by a static read of the 3.2.1 sources, unmeasured against a built release). The wording for a refused read beside a right-hand value the document lacks is unchanged by this entry. See [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* The record of a left-hand value the document lacks, a left-hand marker, or an empty left-hand collection (`Tags: []` under `IN`, `NOT IN` or an ordering comparator, which answer the empty collection as such; between two queries `==` and `!=` compare the empty list whole with each right-hand value: against a right-hand list the two lists compare as lists, so `[] == []` holds and `[] != [1]` passes, and against a scalar they refuse the kinds, a record carrying the operators' own kinds reason (`... not comparable array, int` for an empty list against an integer), `refusal: false`, naming no marker, while the empty list's pairs with the markers themselves are recorded beside it, the refused read's flagged) compared against right-hand values that hold more than one marker (a map a key filter could not decide beside the marker of a refused right-hand query, say) names the markers' sentences in its message, the refused read's first, then the marker the comparison kept, then the rest in value order, numbered `(1) ... (2) ...`, every marker named (the console bounds what it prints of a record; `-o json` and `-o yaml` carry the text whole), a list of up to three sentences whole in every record of the comparison and a longer list named once per comparison where that saves room (the first such record carries it; a later record of the same comparison, another resource lacking the property, say, carries the refused read's sentence and names the record that holds the list by its path, uncut, with any control, bidirectional or zero-width character written as its Rust escape and the backslash doubled, so the pointer maps back to one path; the record's own path field in the structured outputs stays raw, so a consumer reading records per resource undoes that escaping and follows the path to the list; a later record whose pointer would be no shorter than the list keeps the list), under the lead "Refused or undecided selections stand among the right-hand values, reported here so they are not silent" where the record stands for several markers (one marker's record keeps the singular lead it had), and reads `refusal: true` whenever a refused read stands among the right-hand values, the empty collection's record included under `IN`, `NOT IN` and the orderings; this evaluator before the change named the first marker alone, and the empty collection's record read its flag off a refusal's own marker alone, so `Tags: []` and a missing `Tags` beside the same values carried different sentences and flags (no release produced these records). A `-o json` or `-o yaml` consumer that matched one marker's sentence in `error_message` sees the numbered text where two markers stand. See the registered-side paragraph of the bounded-text entry in [docs/CLAUSES.md](docs/CLAUSES.md).
* A filter over a scalar (`Tags[ Key == 'Env' ]` over a string `Tags`) is a registered refusal wherever its sentence is produced, inside a filter predicate as outside one, so a key filter whose right-hand query met it leaves a marker every comparison arm reads as a refused read, as it reads the wrap of a refused walk's marker (a one-object filter refused inside the predicate), which registers no sentence and travels as a flag on the marker instead: an empty left-hand selection compared against that marker is raised and fails the rule closed where it read not applicable at exit 0 with the refusal silent, and the plain shapes over a string `Tags` (`exists`, `!empty`, a comparison) are refused in every clause with `refusal: true`. The refusal's sentence quotes the value's path cut in its middle at the template-part bound with the leaf kept, as every refusal quotes a path. With a capture after `this` (`this[ nm | Key == 'k' ]` over a scalar) the capture is what is refused: the marker is the capture's own refusal, registered under a token and reported once by the capture's warning, so the clause fails closed as it does for any refused capture. For a kept-member `!empty` over such a list (a scalar member beside a list member that holds) the verdict is FAIL with `refusal: true`; this evaluator before the change passed it with `refusal: false` (unmeasured on the releases: no release row holds this shape). The marker a spent regex budget leaves is registered by nobody and keeps every decided answer.
* Whether the marker of a refused right-hand query marks a filter predicate's entry as refused turns on whether its refusal was minted inside the run, other than by the lazy resolution of a file-level `let` (which marks no run), never on how many comparisons inside the run met it: a right-hand query refused inside the run marks the entry refused (a query in the predicate's own comparison, whichever side of the outer comparison the selection stands on), so where the selection is the RIGHT-hand operand of the outer comparison a clause that no resolved right-hand value settles, and that passed on a decided sibling, now fails closed, and where the selection is the LEFT-hand operand a refused member leaves the `some` to its passing sibling and is reported, where a file-level `let`-bound refusal (resolved before the run, or lazily inside it by the first reader, which marks no run), or a capture bound before the run, leaves the entry plain with the refusal's token carried on it; a comparison inside the run that registers a refused read it met keeps the producer's token and makes nothing the run's own, and the wrap a key filter builds for a refused right-hand value carries on its marker the token it was registered under (the refusal's own, recovered from the registry for a marker that carries none; two such markers are ranked by the refusals they name, not by the order they were met in; between a marker's own token and one recovered for another marker's sentence the run that owns a token ranks first, as in every fold, then at equal rank the marker's own token, then minting), so a reader of the marker by its token and a reader of its text through the registry answer alike (the cells are listed under the key-filter entry in [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values)).
* The direct in-predicate shape with no capture is the refusal it is outside a predicate, delivered as the member's marker: the member is UNDECIDED, never deselected as if the predicate had failed it (nor selected as tagless under `!exists`), the siblings are still tested, and the clause over the selection reads the undecided member as its role reads every undecided value, whatever the kept members hold: `Items[ Tags[ Key == 'Env' ] exists ] !empty` over a string-tagged member beside a list-tagged one FAILS closed on the undecided member with the refusal flagged in its record, where the deselection passed it with the refusal silent (a kept member that holds decides `!empty` only among decided members; a cut that let it decide past the refused member, PASS with the refusal on a "passed by a value that holds" line, is withdrawn for refusal markers: `!empty` is monotone and a kept member does answer whether the selection produced anything, but a hard refusal that fails closed is this tool's settled posture, and the argument is recorded for the owner to lift); with no kept member the clause is undecidable the same way, so `Resources.*[ Properties.Tags[ Key == 'Env' ] !exists ] !empty` over a string `Tags` fails closed at the validation failure code with `refusal: true`, where it selected the entry as tagless and passed at exit 0, and `[ ... exists ] !empty` fails closed too (a decided failure before); under `empty` an undecided member alone is undecidable in both roles. The cells are listed under the behavior-change entry for the right-hand marker in [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* A block body that is refused whole, or raises over the read it refused, on a one-object selection beside sibling values (`{ Env exists  ENV exists }` over a map holding exactly those keys beside a list-shaped sibling) is judged by its siblings in both roles, as a body that failed closed on the refusal is, whichever error the body's conjunction held first: a passing sibling decides a `some` block and a failing one an every-entry block, each with the block's own refused-read line, and nothing decided, the block fails closed or raises on that read; a block that returns before that judgement writes each pending value's record and hands every entry it collected up, so no refusal is lost at an early exit. This evaluator before the change returned at once on such a body beside siblings, and keyed the deferral on the error that arrived, so the order of the clauses inside one body decided whether the siblings were consulted.
* The per-resource `Rule = { }` block of the console output prints a nested rule's own `Message` and `Error` lines through the console's refusal pipeline when the record is a refusal's (one line each, collapsed, raw controls escaped, cut at the 4096-character backstop with its marker), and cuts a plain record's message at the same 320-character bound the unattributed section gives it, escaped the same way (the `<< >>` body of a call, which the record carries as the author's text, is printed whole on this line, as a clause's message is, and keeps a zero-width joiner as typed); before this change those lines printed the recorded text as released, controls and all, and a 2 KB template value quoted by a converter's error printed whole there where the unattributed section cut it.
* A parameterized rule whose own `when` could not be evaluated fails with its own sentence, and a call of it keeps that sentence and its refusal kind whether or not the calling clause carries a `<< >>` body. A call with no body now prints the sentence on the `Rule = { }` block's `Message` line and as a `rule <name>` entry of the section for findings that belong to no resource, where the console printed neither; in `-o json` and `-o yaml` the rule report's `messages.custom_message` is the sentence, where it was null. A call with a body prints both: the body, under the relaxed escape set and whole, then the sentence (a refusal's whole, any other cut at the recorded-message bound as the section cuts it), on the `Error` line and after the body in the section entry; the report carries the body as `custom_message` and the sentence as `error_message`, which was null, and the record tree `--print-json` writes carries the sentence as `displaced_message` beside the body in `message` (its kind is not written). A body of blanks is no body. A negated call of such a rule (`not check(..)`) writes the refusal in two entries of that section, the called rule's record and the negation's, each explaining itself.
* The failed-clause tree of the console output writes each of its lines with every control that breaks or hides a line as its Rust escape (`\n`, `\u{1b}`), so a key, a path, a value or a context from the template or the data cannot move the cursor or hide text; the one exception is the rule author's `<< >>` message, which keeps a zero-width joiner and a left-to-right or right-to-left mark as ordinary text, as the per-resource output prints it. In the `junit` report, a text node (a failure's messages, a skip reason, an error) keeps its tab and line feeds, joins a carriage return and line feed pair as one line feed and writes any other control, and U+FFFE and U+FFFF, which XML 1.0 forbids, as its escape; the values of the `name`, `id` and `message` attributes write a tab and a line feed as character references (`&#9;`, `&#10;`), which a parser reads back as the character where a literal one in an attribute value would become a space, so a name that holds a tab and a name that holds a backslash and a `t` stay two names, write a carriage return as its escape `\r` (a reference to one decodes to a raw carriage return for every consumer, so no control other than the tab and the line feed reaches a consumer raw), write a carriage return and line feed pair as `\r` and the line feed reference (the text nodes fold it to one line feed), write a backslash as it is (a file name reads back as it was typed, a Windows path included), and write any other control, U+FFFE, U+FFFF, a zero-width joiner and a bidirectional mark as its escape (a name is an identifier read against other names, unlike the rule author's prose above). A name is read back as typed except that a control other than the tab and the line feed reads as its escape, so a name holding a control and a name holding the typed characters of its escape (a carriage return and a backslash with an `r`, an ESC and `\u{1b}`) read alike in the report (two test-case names that differ only by a control and its typed escape get one JUnit name), and the escaping does not keep every pair of names apart; writing every escape as a reference would keep them apart and hand a raw ESC, a raw carriage return and the bidirectional marks to every consumer, which is refused. The `test` command's case names take the same path: a case name reads as typed in the attribute, where a warning that names it reads with its backslash doubled. The behavior before this change was to print the tree's keys, paths, values and contexts as they were, and to write the `junit` report's attribute values as they were.
* A rule that fails with no check under it (its own `when` could not be evaluated, or a call that carries a `<< >>` body over a rule whose failing block reports nothing: the body is the rule's message, no generic block entry is added beside it, and `-o json` lists the rule with `checks` empty and the body as its message; a rule with no body gets the generic block entry as a check instead) puts the rule record's own message in the `junit` failure element: the author's body under the relaxed escape set, the evaluator's sentence and a refusal's under the strict one. A clause's `<< >>` message in the failure text is written under the relaxed set too, as it is on the console.
* A failing rule is never absent from the `sarif` report. Where no check under the rule says anything (its own `when` failed closed, or a call whose `<< >>` body stands over a silent failing block), the rule's own record is the result, with the same sentences the `junit` failure element carries (the `sarif` text of such a rule-level result is the evaluator's sentence, then the author's `<< >>` body, joined by one space, where the `junit` element lists the body first and joins with line feeds; a part that is empty or only whitespace is left out, so a sentence alone has no trailing space and a body alone has no leading one, and a body is otherwise written as typed, spaces around it included; the `sarif` text of a clause or block result is unchanged), so a refusal the rule's condition met (`; the condition also met: ..`) reaches the `sarif` report too. A called rule's own record is rule-level at every depth: a parameterized rule that fails on its own `when`, or a call with a `<< >>` body over a silent block, nested under another rule has its own result written the same way, and the clause results beside it keep their text. Before this change such a rule had no result at all, and a run that exited with the failure code could write a `sarif` document with none for it.
* A record that fails with no sentence of its own (a type block or an inline `when` whose condition failed closed and whose closing record writes none, or a disjunction with none) lists, beside the entries beneath it, one entry for the refusals its gate marks and its failed conditions name that no entry beneath carries: the refusals alone, whole, flagged as refusals, each told once. It is a block entry in `checks` of `-o json` and `-o yaml` and a line in the unattributed section, and it appears only when there are refusals to tell. Under a rule that has a text of its own (a call's `<< >>` body, or the sentence the body displaced) it is written only as one entry of the rule's `checks` (the refusals alone, whole, flagged as refusals, under the context of the record that carried the first mark), and only where another check under the rule reports; otherwise the rule's sentence joins those refusals and the rule's `checks` stay empty, so its body and its sentence reach the `junit` failure element and the `sarif` result. Either way every format reads each such refusal once, and the author's body is read as it was before, from the rule's own record only where the checks say nothing (in `-o json` the refusal is then in `checks` when the checks report and in `messages.error_message` when they are silent). Three joiners word the refusals a sentence gains, and each belongs to the sentence of the record it sits on (a rule, a type block, an inline `when`, a disjunction or a block): `; the condition also met: ` introduces the refusals that record's OWN failed condition met; `; a nested condition also met: ` introduces, on the sentence of a rule, an access clause that writes its own entry, a type block, an inline `when`, a block or a disjunction, the refusals the failed conditions of the type blocks and `when`s nested in its body met, and of a called rule nested in it that the reporter does not reach, whose run nobody reports (condition refusals, but not the record's own); which nested records leave them to the host depends on the host: beneath a rule with a text or an access clause that writes its own entry, a nested `when` or type block with no sentence writes no entry, reached or not, and its refusals stand behind this joiner on the host's sentence; a type block or an inline `when` with a sentence hands its children no deferral, so beneath it a nested `when` or type block the reporter reaches writes its own entry instead, and the joiner appears on such a host's sentence only for a nested record the reporter does not reach (one beneath a record kind it does not descend into, whose own entry never exists, whether or not it has a sentence of its own: every refusal its failed condition met, a gate mark or any other refused record, is read beneath it and joined there); `; a body clause also met: ` introduces the marks of clauses that ran and that no condition met: the called rule's body clauses, a block's clauses and a disjunction's disjuncts. A refusal beneath a record the reporter does not reach is joined to the nearest ancestor that reports. A sentence that gained several reads them in that order. The sentence of a record with a text of its own written beside its entries is the evaluator's own (an error behind its wrapper, a refusal); the author's `<< >>` text beside entries that report is listed only when nothing beneath it reports, as before. A refusal read under a failed condition (a rule's, a type block's or an inline `when`'s) is a condition refusal wherever it is joined; one read in a clause's body is of the other kind. A record that has a sentence of its own, a block, a disjunction or a bailing type block, writes that sentence as an entry of its own after the entries beneath it, with the refusals no entry carries joined to it, unless an entry beneath already carries the error it quotes; the sentence is told once. An access clause with a message is the exception to that last clause: its entry (its context, the message and the author's `<< >>` text) is written whenever none of its own value checks reports (when one does, those checks carry the account), after what ran under it, and it replaces the marks-only entry a message-less `when` beneath it used to write in `-o json` and `-o yaml` `not_compliant`: the clause's message carries the refusals no entry beneath tells, behind the nested-condition and body-clause joiners, and the records beneath it write no marks entry of their own, so each refusal is read once.
* The console writes the evaluator's own text with the strict escape set: the `Error =` and `Reason =` lines, the failed-clause tree's lines, the evaluator's half of an entry in the section for findings that belong to no resource, the `Error =` line of a plain rule record, and the lines a comparison writer prints. A tag value or a key in such a line that holds a zero-width non-joiner or joiner (U+200C, U+200D), or an emoji sequence joined by one, prints as its escape (`\u{200d}`), so a name with a pasted joiner cannot read like the name without it; the rule author's `<< >>` text keeps the joiner and the marks as typed wherever the console prints it, including the `<< >>` body of a rule call that the rule's own `Message =` line and its entry in that section repeat. This is a behavior change for output that carries such characters: the behavior before this change was to print them in those lines as they were. A `Reason =` or `Error =` line cut at the console's 4096-character backstop now backs up to a word boundary at most 16 characters (it backed up to the last space of the kept text, however far, and so could drop a whole unbroken value or remedy), then cuts by count.
* A failed rule reference (a rule that calls another rule, or a `not` over one) whose callee failed on an error carries that error's own text in its `error_message`, after the reference's own text and a `; ` (the record tree's `message` keeps the `<rule> failed due to error` wording around it), for every reference that failed on an error and not only those inside a `when` condition; where the error is a refusal the record is flagged a refusal, so the console keeps its remedy past the 320-character bound a plain message gets (the console reads the flag; the structured reports do not serialize it), and a failed condition's walk names that refusal once in the rule's sentence. A decided answer that keeps an explanatory message (an empty selection explained) is no longer listed as a finding of a failed condition on the strength of that message. A rule whose verdict a plain error decided keeps that error's kind when the refusals its condition also met are joined to its sentence (`messages.refusal` stays false: the refusals did not decide it); the console prints the plain part cut at the recorded-message bound and the refusals after it whole (on the per-resource block line a plain head prints whole while the joined line fits the 4096-character backstop, and is otherwise cut to the room the refusals leave it, never to a printed head of fewer than 80 characters, its ellipsis included: under that floor the head keeps 80 and the end of the line is cut with the refusal marker, so the refusals lose what the head's 80 characters displace, up to 16 more characters to a word boundary, and whatever the join and the refusals already exceed the backstop by; the cut never backs up past a joiner to drop the refusal it lands in; refusals past the backstop are still cut off), and every structured output (`json`, `yaml`, `sarif` and `junit`) carries the joined text whole, the plain part uncut, since only the console bounds a line; before this change the sentence named the plain error alone and the refusals were named nowhere in it. `cfn-guard test`, which prints statuses and no messages, ends the line of an unmet expectation on a rule whose own `when` failed closed on refusals with `, Reason = <the rule's sentence>`, since no refused-read line is written for this shape; the sentence takes one of two shapes, several refusals joined to it beside the error that decided the rule (a rule whose own head is a refusal's and that joined further refusals gets the same `Reason`, with the refusal bound applied to the plain line, as on the console), or one refusal alone as the sentence. The `test` output moves are, by format: the plain reporter's line ends with `, Reason = ..`, on one line with its controls escaped and the sentence cut as the console cuts it (a plain head at 320 characters, the refusals whole up to the console's backstop; a sentence that is one refusal bounded as a refusal-headed line is); the `-o json` and `-o yaml` reports carry `failed_rules[].reason` (a key written only for a rule in one of the two shapes; a suite with no such rule reports as it did), the raw sentence whole, uncut and unescaped by the console; the `-o junit` failure text ends with `, Reason = ..` for the same sentence, raw and whole. The failing-block record a refused body leaves in a `when` gate now carries the refusal's sentence (the record tree `cfn-guard validate --print-json` writes shows it as that record's `message`), which is where the failed condition's walk reads the refusal from. A call that carries a `<< >>` body over a rule whose failed condition met refusals, with no sentence of the rule's own, reports them in `error_message` (null before), under a head that claims nothing about which error decided the rule ("The rule failed on an error that ended its evaluation; the condition also met: R1; R2"), with the refusals whole and the flag false, since the deciding error was a plain one. A refused read of a missing block value (`MissingBlockValue`) now reports the refusal's sentence, flagged a refusal, where it reported `property [..] is missing`. The per-resource header both console reporters (`cfn` and `tf`) write passes its three template fields, the logical id, the `Type` and the `aws:cdk:path`, through the strict escape before the name is coloured, so a control or a joiner in a logical id or a type prints as its escape.
* A position in the rules file (`Location[file:..., line:..., column:...]`) carries its file name with every control that breaks or hides a line written as its Rust escape (`\n`, `\u{1b}`) and a backslash as written, wherever the position is displayed: the console, the stderr notices, and the record contexts and sentences that `-o json`, `-o yaml`, `sarif` and `junit` carry. No output escapes the position a second time (the notices and the console apply the same non-doubling escape, which leaves an escaped text unchanged), so a file name holding a line feed and one holding a backslash and an `n` are both written `\n` and a reader resolves the name against the file system.
* The `messages.error_message` of a record that carries a refusal (a comparison decided beside a refused read, a right-hand value the evaluator refused to read, a unary check refused over a value) quotes each value it takes from the template, the value a query traversed to and the two values a comparison decided, escaped and cut at 256 printed characters with a marker, `...[N more characters cut]`, where it used to quote the value whole; a right-hand value the evaluator refused to read keeps the sentence `the value to compare to could not be read` followed by the refusal, chosen by the operand's own kind rather than by the record's flag, and an absent right-hand value keeps the missing-property sentence naming the key, beside a refused read among the other values too; the record of a refused left-hand marker compared against a right-hand side the document lacks leads with the right-hand absence named with its side, `The right-hand value is absent: Could not find key <key> inside struct at path <path>`, and carries the refusal after it, printed whole by the console, where it carried the refusal alone with no key named; that record now also carries the absent right-hand value as the value compared with, so the sentence for it, in the console and in the structured report alike, is `the value to compare from could not be read` (the refused read is the finding) followed by that error, which names the right side as absent, where the structured report once said the left was missing; the structured `check` of such a record carries the absent right-hand value under `to` (absent from every other unresolved record, whose shape is unchanged), and the console's per-resource block prints that value after the marker's own block as a `ComparedWith { }` block of its own, its `PropertyPath` and `MissingProperty`, where the block named the right side in the `Error =` line's prose alone. The console's failed-clause tree and the structured report build the sentence of a record with an unresolved operand from one shared builder, which names a refused left-hand read first, else reads the right-hand operand first where it is unresolved (a key filter's marker on the left beside a right-hand side the document lacks is `property [<key>] to compare to is missing`), and words the sentence by the operand's kind: a read the evaluator refused, `the value to compare <from|to> could not be read`; a value the document lacks, the missing-property sentence; and, new, a marker the evaluator could not decide and did not refuse (a key filter's, over a map whose key spent the regex budget), `the value to compare <from|to> could not be decided. Value traversed to [<value>].`, where it read as a property the template lacks. A key filter's marker on the left gets the absence-led message beside a right-hand side the document lacks, and its own reason as the message beside a present right-hand side, where its record carried no message and the console line read `property [] to compare from is missing` with the reason nowhere; neither is flagged as a refusal. A retrieval's own reason for a key the document lacks, or for a key read off a value that is not a map, has its key cut at its end at 256 characters with the marker, its path cut in its MIDDLE to the same bound (the top of the document and the leaf segments kept, the `[L:x,C:y]` location appended whole, so the path still says where the key was missed), each character of either that breaks or hides a line (a line feed, an ESC, a bidi control) written as its escape and the backslash as written, the bound counted on the printed characters so a key of bidi controls cannot carry the line past the console's bound, and the value it quotes escaped in full and cut the same way, where the retrieval writes it, so every sentence that quotes the reason is bounded, a key or a path is spelled as the document spells it, and a right-to-left override in a key cannot reorder the console line. A comparison raised as a `when` condition beside a refusal and a key filter's marker carries the refusal first and the key filter's reason after it, numbered `(1) ... (2) ...`, where the key filter's reason was dropped from the raise (a raise whose recorded reason is a resolved pair's own, the regex engine giving up on one key, keeps that reason first and names the refusal after it), and its record is flagged as a refusal's (`refusal: true`, read off the refusal's token the raise carries beside its text) so the console prints the remedy whole; at most four markers' reasons are numbered after the refusals and the rest are counted once after the numbered parts, `; N more undecided selections not named`; a filter predicate raised beside both carries the refusal alone, since its raise is the entry's marker reason and must stay a registered refusal's text; asserted, the raise is the refusal alone, unnumbered, with `refusal: true`; and a comparison raised beside markers and no refusal (a key filter's marker on each side, or a resolved pair's own undecided reason beside a marker), asserted or gated, is raised on the first reason recorded alone, unnumbered, as the released binaries raised it, since the markers' reasons join a raise only beside a refusal. A consumer of `-o json` or the other structured outputs that matched the old string, or read a value out of the sentence, reads the structured `check` field, which still carries every value whole. A record that is no refusal keeps its sentence as released. A unary check refused over a value the document lacks is now recorded as the refusal it is, so the console prints its sentence whole, the remedy included, on an `Error =` line where it printed nothing of it.
* The console's finding for a refusal record under a resource (the `Check = { }` block of a value the evaluator could not read or the document lacks) lays its two lines out from the record: the record's own sentence on the `Error =` line and the refusal on the `Reason =` line, each one line and cut at 4096 characters with a marker naming the cut, so a refusal is printed exactly once however long it is (every `Reason =` line, a refusal's or not, is the stored reason collapsed onto one line with its line breaks as `; `, its remaining raw controls, an ESC or a bidi override, written as their escapes, and then cut on its printed width at 4096 characters with a marker naming the cut (a refusal's names the explanation, any other reason's names the reason), so an escape never grows a line past the bound; a reason that is no refusal's is never held to the 320-character cut of a recorded message, so a retrieval reason keeps its trailing position, where it was printed as recorded and a raw line break in it made a second console line), where the block printed it on both lines, or printed a sentence cut inside the refusal and the refusal again after it. For an absent value beside a refused read the `Error =` line is the sentence with the retrieval's reason and the refusal after it, and the `Reason =` line that restated the reason is dropped; for a refused marker the `Error =` line is the sentence's head alone and the refusal is the `Reason =` line. The nested `Error = [ ... ]` the sentence carried inside the `Error =` line is gone from the console; `-o json` and the other structured outputs carry the sentence as before, with one exception: a unary check refused over an undecidable marker (`Resources[ Cfg[*].Limits exists ] !empty` over an ambiguous `Cfg`) now carries `Error = [<the refusal>]` alone in its `error_message`, where the sentence's head wrote the bracketed refusal and the join wrote it again, so a consumer that matched the doubled text sees it once; the console's finding for that record writes the refusal once, on its `Reason =` line, with no `Error =` line of its own. Every console line that prints a refusal's sentence, the per-resource lines of a block, a unary check and a decided comparison included, is held to the same 4096-character cap; the verbose tree alone prints a record's message as recorded. The verbose tree's line for a refused LEFT-hand marker beside a right-hand value the document lacks now reads `the value to compare from could not be read` with the absence named with its side before the refusal in its error, from the same shared sentence builder the structured report uses, where it read the right-hand side as the missing property; a left-hand marker that is no refusal keeps the right-hand-first wording. See the behavior-change entries under [docs/CLAUSES.md](docs/CLAUSES.md#marker-among-right-hand-values).
* An access clause's own account of its failure (the block record that carries its sentence and the author's `<< >>` message) is reported AFTER what ran under the clause, in `-o json` and `-o yaml` `not_compliant` and in the console's unattributed section, for every such record: a `not check` that fails closed lists the referenced rule's run first and then the negation's own record, as `not check()` always did (the two spellings now mirror each other; pinned by `eval_tests.rs:the_two_spellings_of_a_negated_reference_report_in_one_order`), and an access clause raised beside a `let`'s key-filter comparisons lists the `let`'s records first and its own sentence last. The block is left out only where one of the clause's own per-value records prints a report of its own (a `Success` prints nothing and leaves the block in). Before, the block came first for every named spelling and was left out whenever any own-context record existed.
* `cfn-guard test` names the refusals a rule's own `when` failed closed on whatever the expectation on the rule, so a FAIL expectation met on such a rule says why as an unmet one does. The default output's met line reads `rule: Expected = FAIL, Reason = <the rule's sentence>` (one line, the console's escape set, bounded as a refusal-headed line is); the `json` and `yaml` reports carry `passed_rules[].reason`, a key written only for a rule that has such a sentence, so a report over a suite with none is byte for byte what it was; the `junit` report writes the sentence as the passed case's `<system-out>` element, and a passed case with none stays the empty `<testcase/>` element. A `when` that failed closed on ONE refusal, with nothing joined to the rule's sentence, now carries that sentence as its `Reason` too, on the met and the unmet line and in every report. An author's `<< >>` text, a plain error with nothing joined and a body assertion that failed on a refusal (which the rule's checks explain) carry no `Reason`.

#### Using Input Parameters

Guard allows you to use input parameters for dynamic data lookups during validation. This feature is particularly useful when you need to reference external data in your rules. However, when specifying input parameter keys, Guard requires that there are no conflicting paths.

##### How to use

1. Use the `--input-params` or `-i` flag to specify files containing input parameters. Multiple input parameter files can be specified and will be combined to form a common context. Input parameter keys can not have conflicting paths.
2. Use the `--data` or `-d` flag to specify the actual template file to be validated.

##### Example Usage

1. Create an input parameter file (e.g., `network.yaml`):

```yaml
NETWORK:
  allowed_security_groups: ["sg-282850", "sg-292040"]
  allowed_prefix_lists: ["pl-63a5400a", "pl-02cd2c6b"]
```

2. Reference these parameters in your guard rule file (e.g., `security_groups.guard`):

```
let groups = Resources.*[ Type == 'AWS::EC2::SecurityGroup' ]

let permitted_sgs = NETWORK.allowed_security_groups
let permitted_pls = NETWORK.allowed_prefix_lists
rule check_permitted_security_groups_or_prefix_lists(groups) {
    %groups {
        this in %permitted_sgs or
        this in %permitted_pls
    }
}

rule CHECK_PERMITTED_GROUPS when %groups !empty {
    check_permitted_security_groups_or_prefix_lists(
       %groups.Properties.GroupName
    )
}
```

3. Create a failing data template (e.g., `security_groups_fail.yaml`):

```yaml
# ---
# AWSTemplateFormatVersion: 2010-09-09
# Description: CloudFormation - EC2 Security Group

Resources:
  mySecurityGroup:
    Type: "AWS::EC2::SecurityGroup"
    Properties:
      GroupName: "wrong"
```

4. Run the validate command:

```
cfn-guard validate -r security_groups.guard -i network.yaml -d security_groups_fail.yaml
```

In this command:

- `-r` specifies the rule file
- `-i` specifies the input parameter file
- `-d` specifies the data file (template) to be validated

##### Multiple Input Parameters

You can specify multiple input parameter files:

```
cfn-guard validate -r rules.guard -i params1.yaml -i params2.yaml -d template.yaml
```

All files specified with `-i` will be combined to form a single context for parameter lookup.

#### Test

Test command is used during the development of guard policy rules files. Test provides a simple integrated unit-test frameworks that allows authors to individually test each policy file for different types of inputs. Unit testing helps authors gain confidence that the rule does indeed conform to expectations. It can also be used as regression tests for rules. Here is example run for `test` command

1. Save the sample policy rules file below as `api_gateway_private_access.guard`:

```
#
# Select from Resources section of the template all ApiGateway resources
# present in the template.
#
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]

#
# Rule intent
# a) All ApiGateway instances deployed must be private
# b) All ApiGateway instances must have atleast one IAM policy condition key to allow access from a VPC
#
# Expectations:
# 1) SKIP when there are not API Gateway instances in the template
# 2) PASS when ALL ApiGateway instances MUST be "PRIVATE" and
#              ALL ApiGateway instances MUST have one IAM Condition key with aws:sourceVpc or aws:SourceVpc
# 3) FAIL otherwise
#
#

rule check_rest_api_is_private when %api_gws !empty {
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

2. Save the sample test file below as `api_gateway_private_access_tests.yaml`:

```yaml
---
- input: {}
  expectations:
    rules:
      check_rest_api_is_private: SKIP
      check_rest_api_has_vpc_access: SKIP
- input:
    Resources: {}
  expectations:
    rules:
      check_rest_api_is_private: SKIP
      check_rest_api_has_vpc_access: SKIP
- input:
    Resources:
      apiGw:
        Type: AWS::ApiGateway::RestApi
  expectations:
    rules:
      check_rest_api_is_private: FAIL
      check_rest_api_has_vpc_access: SKIP
- input:
    Resources:
      apiGw:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types: PRIVATE
  expectations:
    rules:
      check_rest_api_is_private: PASS
      check_rest_api_has_vpc_access: FAIL
- input:
    Resources:
      apiGw:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types: [PRIVATE, REGIONAL]
  expectations:
    rules:
      check_rest_api_is_private: FAIL
      check_rest_api_has_vpc_access: SKIP
- input:
    Resources:
      apiGw:
        Type: AWS::ApiGateway::RestApi
        Properties:
          EndpointConfiguration:
            Types: PRIVATE
          Policy:
            Statement:
              - Action: Allow
                Resource: "*"
                Condition:
                  StringLike:
                    "aws:sourceVPC": vpc-12345678
  expectations:
    rules:
      check_rest_api_is_private: PASS
      check_rest_api_has_vpc_access: PASS
```

3. Run the test command

```bash
cfn-guard test -r api_gateway_private_access.guard -t api_gateway_private_access_tests.yaml
```

![Execution of test](images/guard-test.png)

Read [Guard: Unit Testing](docs/UNIT_TESTING.md) for more information on unit testing. To know about other commands read the [Readme in the guard directory](guard/README.md).

## <a name="references"></a> Rule authoring references

As a starting point for writing Guard rules for yourself or your organisation we recommend following [this official guide](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html)

### Quick links:

[Writing AWS CloudFormation Guard rules](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html)

1. [Clauses](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html#clauses)
2. [Using queries in clauses](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html#clauses-queries)
3. [Using operators in clauses](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html#clauses-operators)
4. [Using custom messages in clauses](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html#clauses-custom-messages)
5. [Combining clauses](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html#combining-clauses)
6. [Using blocks with Guard rules](https://docs.aws.amazon.com/cfn-guard/latest/ug/writing-rules.html#blocks)
7. [Defining queries and filtering](https://docs.aws.amazon.com/cfn-guard/latest/ug/query-and-filtering.html)
8. [Assigning and referencing variables in AWS CloudFormation Guard rules](https://docs.aws.amazon.com/cfn-guard/latest/ug/variables.html)
9. [Composing named-rule blocks in AWS CloudFormation Guard](https://docs.aws.amazon.com/cfn-guard/latest/ug/named-rule-block-composition.html)
10. [Writing clauses to perform context-aware evaluations](https://docs.aws.amazon.com/cfn-guard/latest/ug/context-aware-evaluations.html)

## <a name="functions"></a> Built-in functions & stateful rules

Guard 3.0 introduces support for functions, allowing for stateful rules that can run on a value that's evaluated based
on some properties extracted out of a data template.

### Sample template

Imagine we have a property in our template which consists of a list called as `Collection` and we need to ensure
it has at least 3 items in it.

```yaml
Resources:
  newServer:
    Type: AWS::New::Service
    Collection:
      - a
      - b
```

### Sample rule

We can write a rule to check this condition as follows:

```
let server = Resources.*[ Type == 'AWS::New::Service' ]
rule COUNT_CHECK when %server !empty {
    let collection = %server.Collection.*
    let count_of_items = count(%collection)
    %count_of_items >= 3
    <<
      Violation: Collection should contain at least 3 items
    >>
}
```

Expected outcome is that rule fails showing us the violation message since our template is non-compliant.

For detailed documentation regarding all supported functions, please [follow this link](./docs/FUNCTIONS.md). For limitations of functions usage, please read [this note](./docs/KNOWN_ISSUES.md#function-limitation).

## <a name="registry"></a> AWS Rule Registry

As a reference for Guard rules and rule-sets that contain (on a best-effort basis) the compliance policies that adhere
to the industry best practices around usages across AWS resources, we have recently launched
[AWS Guard Rules Registry](https://github.com/aws-cloudformation/aws-guard-rules-registry).

## <a name="docker"></a> Use Guard as a Docker Image

Guard is also published as an ECR image in [ECR public gallery](https://gallery.ecr.aws/aws-cloudformation/cloudformation-guard) and can be used as an image in a docker container.

### Prerequisites

1. Install docker. Follow [this guide](https://docs.docker.com/engine/install/).
1. Have a directory ready on the host you are downloading the docker image to that contains data templates and Guard rules you are planning to use, we may mount this directory and use the files as input to `cfn-guard`. We'll refer this directory to be called `guard-files` in the rest of this guide

### Usage Guide

To use the binary, we should pull the latest docker image, we may do so using the following command:

```bash
docker pull public.ecr.aws/aws-cloudformation/cloudformation-guard:latest
```

Now go ahead and run the docker image, using the files from directory we have our templates and rules file in, using:

```bash
docker run \
  --mount src=/path/to/guard-files,target=/container/guard-files,type=bind \
  -it public.ecr.aws/aws-cloudformation/cloudformation-guard:latest \
  ./cfn-guard validate -d /container/guard-files/template.yml -r /container/guard-files/rule.guard
```

We should see the evaluation result emitted out on the console.

### Tagging convention

- We use the tag `latest` for the most recent docker image that gets published in sync with `main` branch of the `cloudformation-guard` GitHub repository.
- We use the convention `<branch_name>.<github_shorthand_commit_hash>` for tags of historical docker images

## <a name="ci"></a> Use Guard as a CI tool

Guard is great for CI checks with the Junit output format, making the process of validating or testing your templates seamless and simple. Check out the examples below.

### GitHub Actions

#### Junit

![GitHub Actions](images/github.png)

[Get the template here!](https://github.com/aws-cloudformation/cloudformation-guard/tree/main/guard-examples/ci/.github/workflows/junit-test-and-validate.yml)

#### SARIF

![GitHub Actions](images/sarif-gh.png)

[Get the template here!](https://github.com/aws-cloudformation/cloudformation-guard/tree/main/guard-examples/ci/.github/workflows/sarif-validate.yml)

### CircleCI

#### Junit

![CircleCI](images/circleci.png)

[Get the template here!](https://github.com/aws-cloudformation/cloudformation-guard/tree/main/guard-examples/ci/.circleci/config.yml)

## <a name="pre-commit-hook"></a> Use Guard as a pre-commit hook

Guard is available as a pre-commit hook and offers both the `test` and `validate` operations. You can use them by adding a variation of the following configuration to your `.pre-commit-config.yaml` file:

```yaml
# Since the cfn-guard hook's tagging strategy is incompatible
# with pre-commit's autoupdate feature, you may want to use
# the pre-commit-update hook. If you don't require the autoupdate
# feature, you may skip the pre-commit-update hook.
repos:
  # pre-commit-update hook
  - repo: https://gitlab.com/vojko.pribudic.foss/pre-commit-update
    rev: v0.5.0
    hooks:
      - id: pre-commit-update
        args: [--tag-prefix, cloudformation-guard, pre-commit-v]
  # cfn-guard pre-commit hook
  - repo: https://github.com/aws-cloudformation/cloudformation-guard
    rev: pre-commit-v0.0.2
    hooks:
      # Validate
      - id: cfn-guard
        args:
          - --operation=validate # Specify the validate operation
          - --rules=path/to/rules/ # Rules directory
        files: ^path/to/data/.* # Directory to watch for changes and validate against
      # Test
      - id: cfn-guard
        args:
          - --operation=test # Specify the test operation
          - --dir=path/to/resources/ # Directory that contains rules & their tests
        files: ^path/to/resources.* # Same directory supplied to the --dir arg so that rule and test file changes trigger a run
```

**NOTE**: The args for the pre-commit hook are not identical to the flags you would pass directly to Guard. In the case of this hook, you cannot pass a `data` flag to `validate` as it depends on the `filenames` from the hook and you can only use the `dir` flag for the `test` hook.

## <a name="devcontainer"></a> Contribute using the DevContainer in VSCode

### Setup

**NOTE**: The devcontainer supports zsh and bash with theming and aliases. You can choose which shell you like in the terminal options in your VSCode session.

1. Follow the prerequisite instructions [here](https://code.visualstudio.com/learn/develop-cloud/containers).
1. In VSCode following the install, open the command palette.
1. Search "Dev Containers: Build Container"
1. Once done, open the project inside the container.

### Aliases

- `gval`: `cargo run --bin cfn-guard validate`
- `gtest`: `cargo run --bin cfn-guard test`
- `gparse`: `cargo run --bin cfn-guard parse-tree`
- `cb`: `cargo build`
- `ct`: `cargo nextest run`
- `cn`: `cargo +nightly`

## License

This project is licensed under the Apache-2.0 License.
