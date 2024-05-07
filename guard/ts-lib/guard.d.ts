/* tslint:disable */
/* eslint-disable */
/**
*/
export enum OutputFormatType {
  SingleLineSummary = 0,
  JSON = 1,
  YAML = 2,
  Junit = 3,
  Sarif = 4,
}
/**
*/
export enum ShowSummaryType {
  All = 0,
  Pass = 1,
  Fail = 2,
  Skip = 3,
  None = 4,
}
/**
* .
* A builder to help construct the `Validate` command
*/
export class ValidateBuilder {
  free(): void;
/**
* a list of paths that point to rule files, or a directory containing rule files on a local machine. Only files that end with .guard or .ruleset will be evaluated
* conflicts with payload
* @param {(string)[]} rules
* @returns {ValidateBuilder}
*/
  rules(rules: (string)[]): ValidateBuilder;
/**
* a list of paths that point to data files, or a directory containing data files  for the rules to be evaluated against. Only JSON, or YAML files will be used
* conflicts with payload
* @param {(string)[]} data
* @returns {ValidateBuilder}
*/
  data(data: (string)[]): ValidateBuilder;
/**
* Controls if the summary table needs to be displayed. --show-summary fail (default) or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)
* default is failed
* must be set to none if used together with the structured flag
* @param {any[]} args
* @returns {ValidateBuilder}
*/
  show_summary(args: any[]): ValidateBuilder;
/**
* a list of paths that point to data files, or a directory containing data files to be merged with the data argument and then the  rules will be evaluated against them. Only JSON, or YAML files will be used
* @param {(string)[]} input_params
* @returns {ValidateBuilder}
*/
  input_params(input_params: (string)[]): ValidateBuilder;
/**
* Specify the format in which the output should be displayed
* default is single-line-summary
* if junit is used, `structured` attributed must be set to true
* @param {OutputFormatType} output
* @returns {ValidateBuilder}
*/
  output_format(output: OutputFormatType): ValidateBuilder;
/**
* Tells the command that rules, and data will be passed via a reader, as a json payload.
* Conflicts with both rules, and data
* default is false
* @param {boolean} arg
* @returns {ValidateBuilder}
*/
  payload(arg: boolean): ValidateBuilder;
/**
* Validate files in a directory ordered alphabetically, conflicts with `last_modified` field
* @param {boolean} arg
* @returns {ValidateBuilder}
*/
  alphabetical(arg: boolean): ValidateBuilder;
/**
* Validate files in a directory ordered by last modified times, conflicts with `alphabetical` field
* @param {boolean} arg
* @returns {ValidateBuilder}
*/
  last_modified(arg: boolean): ValidateBuilder;
/**
* Output verbose logging, conflicts with `structured` field
* default is false
* @param {boolean} arg
* @returns {ValidateBuilder}
*/
  verbose(arg: boolean): ValidateBuilder;
/**
* Print the parse tree in a json format. This can be used to get more details on how the clauses were evaluated
* conflicts with the `structured` attribute
* default is false
* @param {boolean} arg
* @returns {ValidateBuilder}
*/
  print_json(arg: boolean): ValidateBuilder;
/**
* Prints the output which must be specified to JSON/YAML/JUnit in a structured format
* Conflicts with the following attributes `verbose`, `print-json`, `output-format` when set
* to "single-line-summary", show-summary when set to anything other than "none"
* default is false
* @param {boolean} arg
* @returns {ValidateBuilder}
*/
  structured(arg: boolean): ValidateBuilder;
/**
*/
  constructor();
/**
* @param {string} payload
* @returns {any}
*/
  try_build_js(payload: string): any;
}
