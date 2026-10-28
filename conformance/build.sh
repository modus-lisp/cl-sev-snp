#!/usr/bin/env bash
# Build the tinfoil-conformance adapter for cl-sev-snp as one executable.
#
#   conformance/build.sh [OUT]      # default OUT: $HOME/scratch/cl-sev-snp-conformance/tinfoil-conformance
#
# The executable carries cl-sev-snp already loaded, so each fixture the harness
# spawns costs a process start, not an ASDF load.  ASDF finds cl-sev-snp and its
# dependencies through CL_SOURCE_REGISTRY or the usual configuration.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$HOME/scratch/cl-sev-snp-conformance/tinfoil-conformance}"
mkdir -p "$(dirname "$out")"
log=/dev/null; [ -n "${VERBOSE:-}" ] && log=/dev/stderr
sbcl --non-interactive \
  --eval '(require :asdf)' \
  --eval "(push #p\"$here/../\" asdf:*central-registry*)" \
  --eval '(asdf:load-system :cl-sev-snp)' \
  --load "$here/adapter.lisp" \
  --eval "(sb-ext:save-lisp-and-die \"$out\" :executable t :toplevel #'cl-sev-snp.conformance:main :save-runtime-options t)" \
  > "$log"
echo "$out"
