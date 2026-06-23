# L4: Automatic Exploration

Goal: generate useful validation inputs automatically.

Required gates:

- angr creates candidate argv/stdin cases.
- string/static-hint input generation works.
- mutation-based expansion works.
- generated tests increase path/output coverage.
- confidence score reflects validation breadth.

Acceptance evidence should show generated inputs, coverage or output-path growth, and confidence score changes tied to the expanded validation set.
