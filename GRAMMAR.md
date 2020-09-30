# Overview
Rulesets can be described by the following ABNF grammar:

```
;Defines the list of rules, assignments, and comments that make up the ruleset
ruleset = 1*([rule / boolean-line / assignment / comment] *WSP CRLF)

;The below definitions are types of valid lines
rule = (base-rule / conditional-rule) [1*WSP output-message]; Rules are either simple boolean checks or conditional checks
boolean-line = (rule 1*("|OR|" 1*WSP rule)); or rule line. Made up of number of rules concatenated with "|OR|"
boolean-line =/ (rule 1*("|AND|" 1*WSP rule)); and rule line. Made up of number of rules concatenated with "|AND|"
assignment = %s"let" 1*WSP variable 1*WSP %s"=" 1*WSP (value / *VCHAR); Assignment rule.
comment = "#" *VCHAR; comment line

;The below definitions describe the basic two types of rules
base-rule = resource-type 1*WSP property-check; simple rule that checks a resource type's property value(s)
conditional-rule = resource-type 1*WSP %s"WHEN" 1*WSP property-check 1*WSP %s"CHECK" 1*WSP property-check; rule that checks values if a certain condition is met
property-check = property-path 1*WSP operand 1*WSP rule-value
resource-type = 1*HEXDIG  2("::" 1*HEXDIG)
property-path = ["."](1*HEXDIG / "*") *("." (1*HEXDIG / "*"))

assignment-value = value / csv / guard-string; assignment values can be valid json values, csv for non json lists, or unquoted strings
rule-value = value / csv / regex / guard-string / variable-dereference; rules can be valid json values, csv for non json lists, regex, unquoted strings, or dereferenced variables
operand = "==" / "!=" / "<" / ">" / "<=" / ">=" / %s"IN" / %s"NOT_IN"
variable-dereference =  ("%" variable) / ("%{" variable "}" )
variable = 1*(HEXDIG / "_")
regex = "/" *VCHAR "/"
csv = *(value-separator *VCHAR); if json array is not valid, guard will split by commas to make a list
guard-string = *(VCHAR / WSP); unquoted string used in the RHS of guard expressions
output-message = "<<" *(VCHAR / WSP)
primitive-value = 1*VCHAR
```

References to `value` refer to the `value` from [JSON's ABNF](https://trac.ietf.org/trac/json/browser/abnf/json.abnf?rev=2) from [RFC7159](https://tools.ietf.org/html/rfc7159), which is provided below for convenience:
```
; Below portions from IETF json.abnf https://trac.ietf.org/trac/json/browser/abnf/json.abnf?rev=2, which is from https://tools.ietf.org/html/rfc7159

begin-array     = ws %x5B ws  ; [ left square bracket
begin-object    = ws %x7B ws  ; { left curly bracket
end-array       = ws %x5D ws  ; ] right square bracket
end-object      = ws %x7D ws  ; } right curly bracket
name-separator  = ws %x3A ws  ; : colon
value-separator = ws %x2C ws  ; , comma
ws = *(
    %x20 /              ; Space
    %x09 /              ; Horizontal tab
    %x0A /              ; Line feed or New line
    %x0D                ; Carriage return
    )
value = false / null / true / object / array / number / string
false = %x66.61.6c.73.65   ; false
null  = %x6e.75.6c.6c      ; null
true  = %x74.72.75.65      ; true
object = begin-object [ member *( value-separator member ) ]
        end-object
member = string name-separator value
array = begin-array [ value *( value-separator value ) ] end-array
number = [ minus ] int [ frac ] [ exp ]
decimal-point = %x2E       ; .
digit1-9 = %x31-39         ; 1-9
e = %x65 / %x45            ; e E
exp = e [ minus / plus ] 1*DIGIT
frac = decimal-point 1*DIGIT
int = zero / ( digit1-9 *DIGIT )
minus = %x2D               ; -
plus = %x2B                ; +
zero = %x30                ; 0
string = quotation-mark *char quotation-mark
char = unescaped /
    escape (
        %x22 /          ; "    quotation mark  U+0022
        %x5C /          ; \    reverse solidus U+005C
        %x2F /          ; /    solidus         U+002F
        %x62 /          ; b    backspace       U+0008
        %x66 /          ; f    form feed       U+000C
        %x6E /          ; n    line feed       U+000A
        %x72 /          ; r    carriage return U+000D
        %x74 /          ; t    tab             U+0009
        %x75 4HEXDIG )  ; uXXXX                U+XXXX
escape = %x5C              ; \
quotation-mark = %x22      ; "
unescaped = %x20-21 / %x23-5B / %x5D-10FFFF
```
