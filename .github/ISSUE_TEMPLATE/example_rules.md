---
name: Example rules
about: Submit example rules to help the community learn to use AWS CloudFormation Guard
title: "[RULES]"
labels: rules
assignees: ''

---

**Describe the example rules**

A clear and concise description of what the rules are demonstrating.

**Ensure you meet our example rules submission policy**

1. Do not mention any security or compliance regimes in custom messages, file names, rule comments, etc.  Example rules are purely for educational purposes and cannot be represented as providing any kind of certification for control regimes like CIS, GDPR, etc
1. Rules should not be duplicates. Please grep the Examples directory contents to ensure that the rules are not already present in another rules file.
1. Rules must include comments or custom messages that describe the function of the rule.
1. If you are adding new rules to an existing rules file, be sure to update the corresponding tests file (YAML file with the same file name prefix) with test inputs which help understand the rules your adding.
1. If you are adding a new rules file, be sure to include a corresponding tests file with test inputs which help understand the rules present in the rules file you are adding.
1. The preferred file system structure is:
    1. **Examples/<meaningful_name>-tests.yaml**
    1. **Examples/<meaningful_name>.guard**
    
   Meaningful file names can include AWS resource types, types of checks being done (e.g. “check-lambda-function.guard”), etc.  
1. Test your rules by running them against the corresponding tests file. Your pull request description must include a markdown-formatted code block showing the result of your test run (not the logs - just the basic output).
1. Rule file names, rule descriptions, etc. should not make mention of the contributor’s identity. (The connection will already be established by merging the commits.)

**NOTE: Please be sure that the templates, rules and logs you provide as part of your bug report do not contain any sensitive information.**

**Additional context**

Add any other context you think is relevant here.