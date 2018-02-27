#!/bin/bash

# Receive the path of a chunk of trace, compress it to a temporary directory
# and delete the chunk.

TRACE_PATH="$1"
TRACE_NAME="$(basename "$TRACE_PATH")"
OUT_PATH="$(mktemp -d)"

cd "$TRACE_PATH/.."

tar czf ${OUT_PATH}/${TRACE_NAME}.tar.gz $TRACE_NAME
echo "New trace chunk archive compressed to ${OUT_PATH}/${TRACE_NAME}.tar.gz"
rm -rf "$TRACE_PATH"
