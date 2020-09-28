# Overview
Rulesets can be described by the following ABNF:

```
ruleset = 1*(line CRLF)
line = rule-line / assignment / comment
rule-line = rule / (rule 1*SP bool-operand 1*SP rule-line)
rule = (base-rule 1*SP output-message) / base-rule
base-rule = check-rule / conditional-rule
check-rule = resource-type 1*SP property-check
check-value = primitive / ("%" variable) / "%{" variable "}"
property-check = property-path 1*SP operand 1*SP check-value
conditional-rule = resource-type 1*SP "WHEN" 1*SP property-check 1*SP "CHECK" 1*SP property-check
variable = 1*(ALPHA) *(ALPHA / DIGIT /"_" / "-")
operand = "==" / "!=" / "<" / ">" / "<=" / ">=" / "IN" / "NOT_IN"
bool-operand = "|OR|" / "|AND|"
resource-type = 1*(ALPHA / DIGIT)  2("::" 1*(ALPHA / DIGIT))
property-path = 1*(["."] 1*ALPHA)
output-message = "<<" primitive
assignment = "let" 1*SP variable 1*SP "=" 1*SP primitive
primitive = 1*(ALPHA / DIGIT)
comment = "#" *VCHAR
```
