#ifndef CFN_GUARD_H
#define CFN_GUARD_H

typedef struct {
  int32_t code;
  char *message;
} extern_err_t;

typedef struct {
  char *content;
  char *file_name;
} validate_input_t;

char* cfn_guard_run_checks(validate_input_t *template, validate_input_t *rules, _Bool verbose, extern_err_t * err);
void cfn_guard_free_string(char *);

#endif
