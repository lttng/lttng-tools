#/bin/bash

SCRIPT_PATH="`readlink -f "$0"`"
export PYTHONPATH="`dirname "$SCRIPT_PATH"`"

set -x
rm -rf /tmp/ctypeslib
mkdir -p /tmp/ctypeslib
CFLAGS="-Wall -Wextra -Werror -std=c99 -pedantic -fpic"
LDFLAGS="-shared"
gcc $CFLAGS $LDFLAGS -o test/data/test-callbacks.so test/data/test-callbacks.c
set +x

error_count=0
for f in test/*.py; do
	if [ "$f" = "test/__init__.py" ] || [ "$f" = "test/util.py" ]; then
		continue
	fi
	echo "$f (python2)"
	python2 $f
	error_count=$(($error_count + $?))
	echo "$f (python3)"
	python3 $f
	error_count=$(($error_count + $?))
done
if [ "$error_count" -eq "0" ]; then
	echo "TEST OK"
else
	echo "TEST **KO**: $error_count"
fi
exit $error_count
