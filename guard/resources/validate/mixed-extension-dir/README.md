# Mixed extension directory

Prose, sitting beside the two templates in this directory so that a test can assert a directory
walk evaluates them and passes over this file. Do not delete.

The content below is deliberately not loadable as YAML, so that a walk which stopped skipping
unrelated files would fail the test outright rather than merely change its output:

  items: [unclosed
	tab-indented: true
