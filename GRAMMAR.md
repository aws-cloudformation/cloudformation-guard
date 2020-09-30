# Overview
Rulesets can be described by the following ABNF grammar:

```
ruleset = 1*((rule / boolean-line / assignment / comment) *WSP CRLF)

boolean-line = (rule 1*("|OR|" 1*WSP rule)) / (rule 1*("|AND|" 1*WSP rule))
assignment = "let" 1*WSP variable 1*WSP "=" 1*WSP primitive
comment = "#" *VCHAR

rule = (base-rule / conditional-rule) [1*WSP output-message]
base-rule = resource-type 1*WSP property-check
conditional-rule = resource-type 1*WSP "WHEN" 1*WSP property-check 1*WSP "CHECK" 1*WSP property-check
resource-type = 1*alphanum  2("::" 1*alphanum)
property-check = property-path 1*WSP operand 1*WSP check-value
check-value = primitive / ("%" variable) / "%{" variable "}" / list
operand = "==" / "!=" / "<" / ">" / "<=" / ">=" / "IN" / "NOT_IN"

variable = 1*(ALPHA / DIGIT / "_")

property-path = 1*(["."] 1*alphanum)
output-message = "<<" *VCHAR
list = "[" [primitive] *("," primitive) "]"
primitive = 1*VCHAR
boolean = "true" / "false"
alphanum = (ALPHA / DIGIT)
```
