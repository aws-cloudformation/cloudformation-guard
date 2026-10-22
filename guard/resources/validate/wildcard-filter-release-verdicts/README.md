# Wildcard-filter release verdicts

The rules and documents in this directory are the probe set behind the release-history sentences on a
filter straight after `[*]` or `.*` in [docs/CLAUSES.md](../../../../docs/CLAUSES.md) (the behavior-change
callouts on a filter after `[*]` over one object and over a map of members, and the paragraph on a filter
through a variable), [docs/KNOWN_ISSUES.md](../../../../docs/KNOWN_ISSUES.md) item 11 and the README's
3.2 bullets. Each cell below is one rules file run over one document with `cfn-guard validate`. The
`3.1.12`, `3.2.0` and `3.2.1` columns were read on binaries built from the commits the upstream
repository's tags of those names point at (`cargo build --release -p cfn-guard` at that commit, rustc
1.77): the `3.2.0` and `3.2.1` tags name the commits that bump the crate version to each release, and the
`3.1.12` tag names a commit whose manifest reads `3.1.2` and whose binary prints `cfn-guard 3.1.2` (the
`3.1.2` tag names the same commit), so the `3.1.12` column is that binary; the `now` column is the current engine,
asserted by the validate test `the_wildcard_filter_fixtures_draw_the_pinned_current_verdicts` in
`guard/tests/validate.rs`, so a move away from it is deliberate. The release columns are recorded, not
asserted. Exit codes: `PASS` and `SKIP` (the rule not applicable) exit 0, `FAIL` exits 19; "panic 101" is
the released CloudFormation reporter's `internal error: entered unreachable code` after it printed
`Status = FAIL` and the rule's `FAIL` line, so the verdict was read and the exit code was the panic's;
"internal error, no verdict" is the same `internal error: entered unreachable code` at exit 101 raised in
the evaluator before any `Status` line, so no verdict was read;
"error 255" is `Unable to resolve type block query: AWS::S3::Bucket`; "FAIL, error 19" is the released
engines' retrieval error on a scalar entry under `.*` then a filter (`Filter on value type that was not a
struct or array int /spec/replicas`), reported as the rule's `FAIL` at exit 19. The exit code of every cell was the
same under the plain invocation, `--verbose` and `--show-summary all`. The table's last three rows are also
the probe set behind the sentence on a refused read beside a value that does not match (the
behavior-change entry on a marker among a comparison's right-hand values in docs/CLAUSES.md, and the
README's bullet on it). docs/KNOWN_ISSUES.md records the same `3.1.12` reading; no release column was
re-measured for this table since it was written.

## What the released trees show

The released binaries' `--verbose` trees print the value a filter's predicate was evaluated against. For a
filter straight after `[*]`, and for `.*` followed by a filter over a list, that value is the member
produced by the nearest earlier `.*`, or the document root when there is none: `Resources[*][ ... ]` was asked
of the document (`Path=[L:0,C:0]`), `Resources.*.Properties.Tags[*][ Key == 'Env' ]` and
`Resources.*.Properties.PolicyDocument.Statement[*][ ... ]` of the resource (`Path=/Resources/F`,
`Path=/Resources/P`). Over a map, `.*` followed by a filter enumerated the map's entries and tested each.
A filter through a variable, `%r[ ... ]` with `let r = Resources`, tested the bound map as one value
(`Path=/Resources`). The engine now enumerates the members, or the list's elements, in every one of these
shapes, and refuses the shapes it cannot read as a collection (a map of scalars, a map with a string entry
beside the resources), at exit 19. Map-shaped tags under a predicate that reads only `Key` and `Value`
against literals are decided by their `{ Key, Value }` list twin, so the two `env_tag_*` rules draw over
`map_shaped_tags.yaml` what they draw over `list_shaped_tags.yaml`: the value `dev` fails `== 'prod'` and
satisfies `!empty`.

## Cells

Rules files are named for the clause they hold; `after_star` is `X[*][ ... ]`, `after_dot_star` is
`X.*[ ... ]`, `after_the_key` is `X[ ... ]`, `through_a_variable` is `let r = X` then `%r[ ... ]`.

| rules file | document | 3.1.12 | 3.2.0 | 3.2.1 | now |
|---|---|---|---|---|---|
| bucket_name_exists_through_a_variable.guard | bucket_beside_a_null_entry.yaml | SKIP | SKIP | SKIP | PASS |
| bucket_name_exists_after_the_key.guard | bucket_beside_a_null_entry.yaml | PASS | PASS | PASS | PASS |
| bucket_name_exists_after_star.guard | bucket_beside_a_null_entry.yaml | SKIP | SKIP | SKIP | PASS |
| bucket_name_exists_after_dot_star.guard | bucket_beside_a_null_entry.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | PASS |
| bucket_name_exists_type_block.guard | bucket_beside_a_null_entry.yaml | error 255 | error 255 | PASS | PASS |
| tags_absent_not_empty_through_a_variable.guard | bucket_beside_a_null_entry.yaml | PASS | PASS | PASS | FAIL |
| tags_absent_not_empty_after_star.guard | bucket_beside_a_null_entry.yaml | PASS | PASS | PASS | FAIL |
| tags_absent_not_empty_after_dot_star.guard | bucket_beside_a_null_entry.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | FAIL |
| tags_absent_not_empty_after_the_key.guard | bucket_beside_a_null_entry.yaml | not run | not run | not run | FAIL |
| buckets_empty_after_star.guard | bucket_beside_a_null_entry.yaml | PASS | PASS | PASS | FAIL |
| buckets_not_empty_after_star.guard | bucket_beside_a_null_entry.yaml | FAIL | FAIL | FAIL | PASS |
| bucket_name_exists_through_a_variable.guard | bucket_beside_a_null_element_list.yaml | PASS | PASS | PASS | PASS |
| bucket_name_exists_after_the_key.guard | bucket_beside_a_null_element_list.yaml | PASS | PASS | PASS | PASS |
| bucket_name_exists_after_star.guard | bucket_beside_a_null_element_list.yaml | SKIP | SKIP | SKIP | PASS |
| bucket_name_exists_after_dot_star.guard | bucket_beside_a_null_element_list.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | PASS |
| bucket_name_exists_type_block.guard | bucket_beside_a_null_element_list.yaml | error 255 | error 255 | SKIP | PASS |
| tags_absent_not_empty_through_a_variable.guard | bucket_beside_a_null_element_list.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | FAIL |
| tags_absent_not_empty_after_star.guard | bucket_beside_a_null_element_list.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | FAIL |
| tags_absent_not_empty_after_dot_star.guard | bucket_beside_a_null_element_list.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | FAIL |
| tags_absent_not_empty_after_the_key.guard | bucket_beside_a_null_element_list.yaml | not run | not run | not run | FAIL |
| type_after_star_without_a_filter.guard | bucket_beside_a_null_element_list.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | FAIL |
| buckets_exist_after_star.guard | bucket_beside_a_null_element_list.yaml | SKIP | SKIP | SKIP | PASS |
| bucket_name_exists_after_star.guard | two_buckets.yaml | SKIP | SKIP | SKIP | PASS |
| bucket_name_exists_after_dot_star.guard | two_buckets.yaml | PASS | PASS | PASS | PASS |
| buckets_empty_after_star.guard | two_buckets.yaml | PASS | PASS | PASS | FAIL |
| buckets_not_empty_after_star.guard | two_buckets.yaml | FAIL | FAIL | FAIL | PASS |
| buckets_exist_after_star.guard | two_buckets.yaml | SKIP | SKIP | SKIP | PASS |
| type_after_star_without_a_filter.guard | two_buckets.yaml | FAIL | FAIL | FAIL | FAIL |
| member_key_exists_empty_after_star.guard | two_buckets.yaml | PASS | PASS | PASS | PASS |
| member_key_exists_not_empty_after_star.guard | two_buckets.yaml | FAIL | FAIL | FAIL | FAIL |
| member_key_exists_empty_after_dot_star.guard | two_buckets.yaml | PASS | PASS | PASS | PASS |
| tags_absent_not_empty_after_star.guard | two_buckets.yaml | PASS | PASS | PASS | PASS |
| bucket_name_exists_after_star.guard | two_buckets_list.yaml | SKIP | SKIP | SKIP | PASS |
| bucket_name_exists_after_dot_star.guard | two_buckets_list.yaml | SKIP | SKIP | SKIP | PASS |
| buckets_not_empty_after_star.guard | two_buckets_list.yaml | FAIL | FAIL | FAIL | PASS |
| buckets_not_empty_after_dot_star.guard | two_buckets_list.yaml | FAIL | FAIL | FAIL | PASS |
| bucket_name_exists_after_star.guard | bucket_beside_a_string_entry.yaml | SKIP | SKIP | SKIP | FAIL |
| bucket_name_exists_after_dot_star.guard | bucket_beside_a_string_entry.yaml | FAIL, panic 101 | FAIL, panic 101 | FAIL, panic 101 | PASS |
| buckets_empty_after_star.guard | bucket_beside_a_string_entry.yaml | PASS | PASS | PASS | FAIL |
| buckets_not_empty_after_star.guard | bucket_beside_a_string_entry.yaml | FAIL | FAIL | FAIL | FAIL |
| allow_all_statement_empty_after_star.guard | one_object_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| allow_all_statement_empty_after_dot_star.guard | one_object_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| allow_statement_empty_after_star.guard | one_object_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| allow_all_statement_empty_after_star.guard | one_element_list_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| allow_all_statement_empty_after_dot_star.guard | one_element_list_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| allow_statement_empty_after_star.guard | one_element_list_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| allow_statement_empty_after_dot_star.guard | one_element_list_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| star_action_statement_empty_after_dot_star.guard | one_element_list_allow_all_statement.yaml | PASS | PASS | PASS | FAIL |
| security_context_absent_not_empty_after_dot_star.guard | spec_with_a_scalar_beside_sub_maps.yaml | FAIL, error 19 | FAIL, error 19 | FAIL, error 19 | PASS |
| security_context_absent_not_empty_after_dot_star.guard | spec_of_scalars.yaml | FAIL, error 19 | FAIL, error 19 | FAIL, error 19 | FAIL |
| env_tag_value_is_prod_after_star.guard | map_shaped_tags.yaml | SKIP | SKIP | SKIP | FAIL |
| env_tag_not_empty_after_star.guard | map_shaped_tags.yaml | FAIL | FAIL | FAIL | PASS |
| env_tag_value_is_prod_after_star.guard | list_shaped_tags.yaml | SKIP | SKIP | SKIP | FAIL |
| env_tag_not_empty_after_star.guard | list_shaped_tags.yaml | FAIL | FAIL | FAIL | PASS |
| bucket_name_exists_after_star.guard | bucket_without_a_bucket_name.yaml | not run | not run | not run | FAIL |
| bucket_name_exists_after_the_key.guard | bucket_without_a_bucket_name.yaml | not run | not run | not run | FAIL |
| tags_absent_not_empty_through_a_variable_bound_to_properties.guard | scalar_properties_without_tags.yaml | not run | not run | not run | FAIL |
| mode_ref_equals_captured_keys_gate.guard | captured_modes_beside_a_refused_walk.yaml | SKIP | SKIP | SKIP | SKIP |
| some_names_not_in_captured_keys_gate.guard | captured_modes_beside_a_refused_walk.yaml | SKIP | SKIP | SKIP | SKIP |
| owner_equals_tag_names_empty.guard | bucket_owner_beside_map_shaped_tags.yaml | internal error, no verdict | internal error, no verdict | internal error, no verdict | PASS |
| tag_specifications_absent_gate_through_a_variable.guard | launch_template_with_tag_specifications.yaml | not run | not run | not run | SKIP |
| type_or_name_not_empty_after_star.guard | bucket_with_rules_members.yaml | not run | not run | not run | FAIL |
| type_is_bucket_not_empty_after_star.guard | bucket_with_rules_members.yaml | not run | not run | not run | FAIL |
| description_absent_empty_after_star.guard | ingress_list_without_a_description.yaml | not run | not run | not run | FAIL |
| description_absent_empty_after_star.guard | ingress_list_with_a_description.yaml | not run | not run | not run | PASS |
| type_tag_not_empty_after_star.guard | list_shaped_tags.yaml | not run | not run | not run | FAIL |
| assume_role_document_gate_after_star.guard | two_roles.yaml | not run | not run | not run | FAIL |
| assume_role_document_gate_after_star.guard | one_role.yaml | not run | not run | not run | FAIL |
| type_tag_not_empty_after_star.guard | map_shaped_tags.yaml | not run | not run | not run | FAIL |

## Notices

Whether the current engine writes the `[*]` member notice (`DEPRECATION: the filter after `[*]` at ...`) to
stderr for a cell, beside the verdict the Cells table pins, so a verdict that did not move is told from a
selection that did. Asserted by the validate test `the_wildcard_filter_fixtures_pin_whether_the_member_notice_fires`,
which reads this table (the rules file in backticks, so the Cells reader passes these rows over). `BucketA
exists` found no `BucketA` on the document in the releases and finds none on a member now: nothing moved,
nothing said. `Tags !exists` held on the document in the releases, which selected it whole, and selects the
untagged members now: the selection moved, the verdict did not (over two buckets) or did (over the null
entry, which the assertion fails closed on), and the notice says so either way. `Type == 'AWS::S3::Bucket'
or Name == 'r'` over `Rules: { A: { Type: X }, B: { Name: q } }` names two keys each held by one member; the
releases asked it of the resource, which holds `Type: AWS::S3::Bucket`, and selected the resource whole, so
`!empty` passed there and fails over the members, none of which is kept: the notice names `Type`, the key the
resource holds and the predicate held through, and says none kept. The one-key `Type == 'AWS::S3::Bucket'`
over the same members is the same hold on the resource's own `Type` and is announced the same way; `Type ==
'X'`, which the resource's own `Type` fails, is not (the releases selected nothing there, and nothing is kept
now).

| rules file | document | member notice now |
|---|---|---|
| `member_key_exists_empty_after_star.guard` | two_buckets.yaml | no |
| `member_key_exists_not_empty_after_star.guard` | two_buckets.yaml | no |
| `member_key_exists_empty_after_dot_star.guard` | two_buckets.yaml | no |
| `tags_absent_not_empty_after_star.guard` | two_buckets.yaml | yes |
| `tags_absent_not_empty_after_star.guard` | bucket_beside_a_null_entry.yaml | yes |
| `type_or_name_not_empty_after_star.guard` | bucket_with_rules_members.yaml | yes |
| `type_is_bucket_not_empty_after_star.guard` | bucket_with_rules_members.yaml | yes |
| `description_absent_empty_after_star.guard` | ingress_list_without_a_description.yaml | no |
| `description_absent_empty_after_star.guard` | ingress_list_with_a_description.yaml | no |
| `type_tag_not_empty_after_star.guard` | list_shaped_tags.yaml | no |
| `assume_role_document_gate_after_star.guard` | two_roles.yaml | no |
| `assume_role_document_gate_after_star.guard` | one_role.yaml | no |
| `type_tag_not_empty_after_star.guard` | map_shaped_tags.yaml | yes |

The `now` verdicts of the released-column cells did not change between the engine they were first read on
and the one this directory was committed at. A release column reading "not run" marks a cell the released
binaries were never run over: the three documents added for the current engine
(`bucket_without_a_bucket_name.yaml`, `scalar_properties_without_tags.yaml`,
`launch_template_with_tag_specifications.yaml`) and the one rule added for it,
`tags_absent_not_empty_after_the_key.guard`, over the two null documents, the two held-key cells
(`type_or_name_not_empty_after_star.guard` and `type_is_bucket_not_empty_after_star.guard` over
`bucket_with_rules_members.yaml`, a predicate that held on the bucket through its own `Type`, which the `Rules`
members hold each for themselves), the list-shaped twins of the
documented one-object cells (`description_absent_empty_after_star.guard` over the two ingress lists,
`type_tag_not_empty_after_star.guard` over the list-shaped tags and over its map-shaped sibling), which pin
the reading the list form keeps beside the map form, and `assume_role_document_gate_after_star.guard` over one
role and over two, the projecting binding's `[*]` over a map of Properties maps (the spelling
docs/KNOWN_ISSUES.md item 15 documents; `two_roles.yaml` is a map of two roles, not a list); what the releases drew there is
stated in the docs as an inference from the mechanism the trees show on the other cells, never as a
measurement. The `.*` cells
over `bucket_beside_a_string_entry.yaml` and over the one-object statement read `FAIL, panic 101` and
`PASS` in the releases for different reasons than the documents that look like them: the trees for those
two cells are what the CLAUSES sentences cite.
