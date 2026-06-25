#!/usr/bin/env bash
# Region/line coverage of the napi binding (src/lib.rs), driven by the node test suite.
# The #[napi]/#[napi(object)] macro lines (generated FromNapiValue + arg-validation, unreachable from
# typed TS) and the unreachable `escalate` arm cap LINE coverage; REGION coverage is the real measure.
set -euo pipefail
cd "$(dirname "$0")"
eval "$(cargo llvm-cov show-env --export-prefix)"
cargo llvm-cov clean --workspace
npm run build:debug
node --test test/*.test.mjs
cargo llvm-cov report --summary-only
