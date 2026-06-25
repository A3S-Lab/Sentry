#!/usr/bin/env bash
# Region/line coverage of the PyO3 binding (src/lib.rs), driven by the python test suite.
# The only misses are the #[pymethods] macro attribute lines (generated codegen) and the unreachable
# `escalate` arm; REGION coverage is the real measure. Needs the .venv from `maturin develop`.
set -euo pipefail
cd "$(dirname "$0")"
eval "$(cargo llvm-cov show-env --export-prefix)"
cargo llvm-cov clean --workspace
. .venv/bin/activate
maturin develop
python -m unittest discover -s tests -t .
cargo llvm-cov report --summary-only
