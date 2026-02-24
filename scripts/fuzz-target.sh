#!/bin/bash
# scripts/fuzz-target.sh — Launch JOTL fuzz-v1 target server
#
# Usage:
#   bash scripts/fuzz-target.sh [socket_path]
#
# Default socket: /tmp/jam_target.sock
#
# Then in another terminal:
#   cd jam-conformance/fuzz-proto
#   python minifuzz/minifuzz.py -d examples/0.7.2/no_forks \
#     --target-sock /tmp/jam_target.sock

SOCKET_PATH="${1:-/tmp/jam_target.sock}"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

exec sbcl --dynamic-space-size 4096 --noinform --disable-debugger \
     --eval '(require :asdf)' \
     --eval "(pushnew #p\"$DIR/\" asdf:*central-registry*)" \
     --eval "(pushnew #p\"$DIR/crypto/\" asdf:*central-registry*)" \
     --eval "(pushnew #p\"$DIR/jamvm/\" asdf:*central-registry*)" \
     --eval '(asdf:load-system :jotl)' \
     --eval "(jotl:run-fuzz-target :socket \"$SOCKET_PATH\")" \
     --eval '(sb-ext:exit :code 0)'
