#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

source_dir="$1"

# Run make quietly to check if a Makefile exists
make_output=$(make -C "$source_dir" -q 2>&1)
make_exit_status=$?

# Check the return status of make -q
if [ $make_exit_status -eq 2 ]; then
    # It seems the Makefiles don't exist. Most likely the user forgot to
    # setup their tree.
    echo "$make_output"
    echo -e "\033[33mMake couldn't find a Makefile: did you run ./bootstrap and ./configure ?\033[0m"
    exit 1
fi

# Check if compile_commands.json does not exist in the source directory and if bear is installed
if [ ! -f "$source_dir/compile_commands.json" ] && which bear >/dev/null 2>&1; then
    # Bear is installed and compile_commands.json is not present
    # Perform a make clean since compile_commands.json is missing and bear is installed
    make -C "$source_dir" clean

    # Prefix bear to the make command
    command_prefix="bear -- "
fi

# Run make with or without bear prefix, depending on the condition above
eval "${command_prefix}"make -C "$source_dir" -j "$(nproc)"
