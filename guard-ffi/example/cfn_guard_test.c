#include <stdio.h>
#include <stdlib.h>
#include "cfn_guard.h"

int main() {
  extern_err_t err;
  validate_input_t data, rules;
  data.content = "foo:\n  bar: true";
  data.file_name = "data.json";
  rules.content = "rule check_foo { foo.bar == true }";
  rules.file_name = "check.rule";
  char* result = cfn_guard_run_checks(&data, &rules, 0, &err);
  if (err.code == 0) {
    printf(result);
    cfn_guard_free_string(result);
    cfn_guard_free_string(err.message);
  } else {
    printf("error: %i (%s)\n", err.code, err.message);
    cfn_guard_free_string(err.message);
    cfn_guard_free_string(result);
  }
  return 0;
}
