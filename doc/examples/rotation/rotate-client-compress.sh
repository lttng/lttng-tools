#!/bin/bash

# Receive the path of a chunk of trace, compress it to /tmp/ and delete the
# chunk.

TRACE_PATH=$1
TRACE_NAME=$(basename $TRACE_PATH)

cd $TRACE_PATH
cd ..

tar czf /tmp/${TRACE_NAME}.tar.gz $TRACE_NAME
echo "New chunk compressed in /tmp/${TRACE_NAME}.tar.gz"
rm -rf $TRACE_PATH
