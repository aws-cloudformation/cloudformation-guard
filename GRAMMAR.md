# Overview
Rulesets can be defined by the following ABNF grammar:

```abnf
;Defines the list of rules, assignments, and comments that make up the ruleset.

ruleset = 1*([rule / clause / assignment / comment / import-statement] *WSP CRLF)

;The below definitions are types of valid lines.
rule = (base-rule / conditional-rule) [1*WSP output-message]; Rules are either simple boolean checks or conditional checks
clause = (rule 1*(%s"|OR|" 1*WSP rule)) / (rule 1*(%s"|AND|" 1*WSP rule)); 'And' or 'Or' clause. Made up of number of rules concatenated with "|AND|" or "|OR|".
                                                                         ; clause cannot contain both expression forms |OR| and |AND|.
assignment = %s"let" 1*WSP variable 1*WSP %s"=" 1*WSP assignment-value; Assignment rule.
comment = "#" vchar-sp; Comment line
import-statement = %s"import" 1*WSP file-path
file-path = ["/"] (file-part) *("/" file-part )
file-part = "." / ".." / "~" / VCHAR*

;The below definitions describe the basic two types of rules and optional output message.
base-rule = resource-type 1*WSP property-comparison; Simple rule that compares a resource type's property value(s) with some value(s).
conditional-rule = resource-type 1*WSP %s"WHEN" 1*WSP property-comparison 1*WSP %s"CHECK" 1*WSP property-comparison; Rule that checks values if a certain condition is met.
output-message = "<<" vchar-sp

;The below definitions comprise all available property comparisons.
; Property comparisons can check string equality, membership in lists, or compare two numbers.
property-comparison = property-path 1*WSP equality-operand 1*WSP eq-value ; Equality comparison
property-comparison =/ property-path 1*WSP greater-less-operand 1*WSP greater-less-value; Number comparison
property-comparison =/ property-path 1*WSP list-operand 1*WSP list-value;  Membership in lists

;The below definitions comprise operands for comparisons
equality-operand = "==" / "!="
greater-less-operand =  "<" / ">" / "<=" / ">="
list-operand = %s"IN" / %s"NOT_IN"

; The below definitions define the left hand side values for comparisons and assignments 
resource-type = 1*alphanum  2("::" 1*alphanum)
property-path = ["."] (1*alphanum / wildcard) *("." (1*alphanum / wildcard))
variable = 1*(alphanum / "_")

;The below definitions define right hand side values for both assignments and comparisons
assignment-value = number / list-value / unquoted-string; Assignment values can be valid json lists, csv for non json lists, or unquoted strings.
eq-value =  unquoted-string / regex / variable-dereference; Comparisons using equality operators are simply stripped of whitespace and compared. Regex patterns are matched.
greater-less-value = number / variable-dereference; All non equality comparison operators require numbers for comparison.
list-value = csv / array / variable-dereference; Lists are comma separated or JSON arrays defined in the below JSON abnf.
variable-dereference =  ("%" variable) / ("%{" variable "}" ); Regular and environment variables, respectively
regex = "/" vchar-sp "/"; Regular expression in rust regex syntax: https://docs.rs/regex/1.3.9/regex/#syntax
csv = csv-value *(value-separator csv-value); If json array is not valid, cfn-guard will split by commas to make a list (elements can be null)
csv-value = [unquoted-string]
unquoted-string = VCHAR vchar-sp; Unquoted string used in the RHS of cfn-guard assignments and equality comparisons.

wildcard = %s"*"
vchar-sp = *(VCHAR / WSP)
alphanum = (ALPHA / DIGIT)
```

References to `value` refer to the `value` from [JSON's ABNF](https://trac.ietf.org/trac/json/browser/abnf/json.abnf?rev=2) from [RFC7159](https://tools.ietf.org/html/rfc7159), which is provided below for convenience:
```abnf
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
