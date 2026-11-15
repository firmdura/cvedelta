# Renderer expected outputs

Original fixtures and formatting: Apache-2.0.

Each JSON and Markdown pair is the expected rendering of a complete, fixed
report from `testdata/provenance/synthetic/`. These expected files, also called
goldens, let tests detect changes in output bytes. Their input reports are
defined independently of the comparison engine, and renderer tests never
regenerate the expected files.

The cases cover all five finding categories, disabled change checks,
provenance differences, comparable reports with no changes, and incomparable
reports with no changes even when change checks are disabled.

JSON follows the schema and model's member order, uses two-space indentation
and Go's JSON HTML escaping, and ends with one newline. Decoding it must
reproduce every report field.

Markdown places source strings in code spans. It displays line breaks,
control and formatting characters, and code, table and HTML delimiters as
visible escapes. Source URLs remain text even in renderers that automatically
link bare URLs. Every record and attribute is included without truncation.
