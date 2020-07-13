# CloudFormation Guard Examples

The files in this directory are intended solely to provide a starting point for experimentation.

## Submitting example rules

Thank you so much for your contributions to cfn-guard. Please comply with the following guidelines when submitting example rules to cfn-guard. Following these checks will help ensure a quick review of your pull request.

1. Do not mention any security or compliance regimes in custom messages, file names, rule comments, etc.  Example rules are purely for educational purposes and cannot be represented as providing any kind of certification for control regimes like CIS, GDPR, etc
1. Rules should not be duplicates.  Please grep the Examples directory contents to ensure that the rules are not already present in another ruleset.
1. Rules must include comments or custom messages that describe the function of the rule.
1. Please sort the rules in your ruleset contents alphabetically to make it easy for the community to search for your contributions.  If you feel strongly that there's a more intutive way to organize the contents of the ruleset, please provide an explanation of why in your pull request's description and we'll take that into consideration when reviewing the pull request.
1. Please keep variable assignments at the top of the ruleset file, also sorted alphabetically and with at least one empty line between them and the start of the rules.
1. If you are adding new rules to an existing ruleset file and/or the new rules operate on resources or properties not present in an existing template, be sure to include an update to the existing template to add these new resources or properties.
1. Rules involving new example templates must come with a copy of that template. The preferred file system structure is:
    1. **Examples/<meaningful_name>-template.yaml** (or JSON) to meet the cfn-lint file naming convention
    1. **Examples/<meaningful_name>.ruleset**
    
   Meaningful file names can include AWS resource types, types of checks being done (e.g. “check-lambda-function.ruleset”), etc.  
1. Test your rules by running them against a template. Your pull request description must include a markdown-formatted code block showing the result of your test run (not the logs - just the basic output) and that the rule correctly failed and passed on the resource types it applies to. The easiest way to do that is typically to include a resource that would pass and a resource that would fail in the same template you run your test against.
1. Rule set names, rule descriptions, etc. should not make mention of the contributor’s identity. (The connection will already be established by merging the commits.)

