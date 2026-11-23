#ifndef CFN_GUARD_H
#define CFN_GUARD_H

/* int32_t below. The header declared it without including anything, so it did not compile on its
 * own: cfn_guard_test.c includes only stdio.h and stdlib.h, neither of which provides int32_t, and
 * `gcc -std=c11 -c cfn_guard_test.c` failed with "unknown type name 'int32_t'". */
#include <stdint.h>

/* `bool` below, rather than the `_Bool` this used to declare. `_Bool` is a C keyword and is not a
 * type in C++, so the header could not be included from C++ even after the parameter rename. In C99
 * and later `bool` is a macro for `_Bool`, so the declared type and its width are unchanged. */
#ifndef __cplusplus
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  int32_t code;
  char *message;
} extern_err_t;

typedef struct {
  char *content;
  char *file_name;
} validate_input_t;

/* Every pointer in `data` and `rules` must be non-null and must hold valid UTF-8. A null one gives
 * code 23 and a non-UTF-8 one gives code 24, both naming the field in `err.message`.
 *
 * The first parameter was named `template`, which is a reserved word in C++, so a C++ translation
 * unit failed at the `#include` with "expected ',' or '...' before 'template'". It is now `data`,
 * matching the Rust side. */
char *cfn_guard_run_checks(validate_input_t data, validate_input_t rules, bool verbose,
                           extern_err_t *err);
void cfn_guard_free_string(char *);

#ifdef __cplusplus
}
#endif

#endif
