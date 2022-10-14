#include <stdio.h>
#include <stdlib.h>
#include "cfn_guard.h"

void run_rule() {
  extern_err_t err;
  validate_input_t data, rules;
  data.content = "foo:\n  bar: true";
  data.file_name = "data.json";
  rules.content = "rule check_foo { foo.bar == true }";
  rules.file_name = "check.rule";
  char* result = cfn_guard_run_checks(data, rules, 0, &err);
  if (err.code == 0) {
    printf("%s\n", result);
    cfn_guard_free_string(result);
    cfn_guard_free_string(err.message);
  } else {
    printf("error: %i (%s)\n", err.code, err.message);
    cfn_guard_free_string(err.message);
    cfn_guard_free_string(result);
  }
}

void print_version() {
  extern_err_t err;
  char *result = cfn_guard_version(&err);
  printf("%s\n", result);
  cfn_guard_free_string(result);
  cfn_guard_free_string(err.message);
}

int main() {
  run_rule();
  print_version();
  return 0;
}
