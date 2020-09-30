# Overview
Rulesets can be described by the following ABNF grammar:

```
ruleset = 1*([rule / boolean-line / assignment / comment] *WSP CRLF)

boolean-line = (rule 1*("|OR|" 1*WSP rule)); or rule line
boolean-line =/ (rule 1*("|AND|" 1*WSP rule)); and rule line

assignment = "let" 1*WSP variable 1*WSP "=" 1*WSP (primitive-value / list)
comment = "#" *VCHAR

rule = (base-rule / conditional-rule) [1*WSP output-message]
base-rule = resource-type 1*WSP property-check; simple rule that checks a resource type's property value(s)
conditional-rule = resource-type 1*WSP "WHEN" 1*WSP property-check 1*WSP "CHECK" 1*WSP property-check; rule that checks values if a certain condition is met
resource-type = 1*alphanum  2("::" 1*alphanum)
property-check = property-path 1*WSP operand 1*WSP rule-value
rule-value = primitive-value / list / regex / variable-dereference ; https://github.com/aws-cloudformation/cloudformation-guard/blob/98c6b6c9a15ec51cb9575767f19134e5819510d1/cfn-guard/src/guard_types.rs#L28-L33
operand = "==" / "!=" / "<" / ">" / "<=" / ">=" / "IN" / "NOT_IN"

variable-dereference =  "%" variable; regular variable
variable-dereference =/ "%{" variable"}"; environment variable
variable = 1*(HEXDIG / "_")
regex = "/" *VCHAR "/"
list = "[" *VCHAR *("," *VCHAR) "]"

property-path = 1*(["."] (1*alphanum / "*"))
output-message = "<<" *VCHAR
primitive-value = (1*VCHAR)

```
