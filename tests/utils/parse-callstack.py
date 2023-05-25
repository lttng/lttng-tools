#!/usr/bin/env python3
#
# Copyright (C) 2017 Francis Deslauriers <francis.deslauriers@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only
#

import sys
import bisect
import subprocess
import re

def addr2line(executable, addr):
    """
        Uses binutils' addr2line to get function containing a given address
    """
    cmd =['addr2line']

    cmd += ['-e', executable]

    # Print function names
    cmd += ['--functions']

    # Expand inlined functions
    cmd += ['--addresses', addr]

    status = subprocess.run(cmd, stdout=subprocess.PIPE, check=True)

    addr2line_output = status.stdout.decode("utf-8").splitlines()
    # addr2line's output is made of 3-tuples:
    #   - address
    #   - function name
    #   - source location
    if len(addr2line_output) % 3 != 0:
        raise Exception('Unexpected addr2line output:\n\t{}'.format('\n\t'.join(addr2line_output)))

    function_names = []
    for address_line_number in range(0, len(addr2line_output), 3):
        function_name = addr2line_output[address_line_number + 1]

        # Filter-out unresolved functions
        if "??" not in function_name:
            function_names.append(addr2line_output[address_line_number + 1])

    return function_names

def extract_user_func_names(executable, raw_callstack):
    """
        Given a callstack from the Babeltrace CLI output, returns a set
        containing the name of the functions. This assumes that the binary have
        not changed since the execution.
    """
    recorded_callstack = set()

    # Remove commas and split on spaces
    for index, addr in enumerate(raw_callstack.replace(',', '').split(' ')):
        # Consider only the elements starting with '0x' which are the
        # addresses recorded in the callstack
        if '0x' in addr[:2]:
            funcs = addr2line(executable, addr)
            recorded_callstack.update(funcs)

    return recorded_callstack

def extract_kernel_func_names(raw_callstack):
    """
        Given a callstack from the Babeltrace CLI output, returns a set
        containing the name of the functions.
        Uses the /proc/kallsyms procfile to find the symbol associated with an
        address. This function should only be used if the user is root or has
        access to /proc/kallsyms.
    """
    recorded_callstack = set()
    syms=[]
    addresses=[]
    # We read kallsyms file and save the output
    with open('/proc/kallsyms') as kallsyms_f:
        for line in kallsyms_f:
            line_tokens = line.split()
            addr = line_tokens[0]
            symbol = line_tokens[2]
            addresses.append(int(addr, 16))
            syms.append({'addr':int(addr, 16), 'symbol':symbol})

    # Save the address and symbol in a sorted list of tupple
    syms = sorted(syms, key=lambda k:k['addr'])
    # We save the list of addresses in a seperate sorted list to easily bisect
    # the closer address of a symbol.
    addresses = sorted(addresses)

    # Remove commas and split on spaces
    for addr in raw_callstack.replace(',', '').split(' '):
        if '0x' in addr[:2]:
            # Search the location of the address in the addresses list and
            # deference this location in the syms list to add the associated
            # symbol.
            loc = bisect.bisect(addresses, int(addr, 16))
            recorded_callstack.add(syms[loc-1]['symbol'])

    return recorded_callstack

# Regex capturing the callstack_user and callstack_kernel context
user_cs_rexp='.*callstack_user\ \=\ \[(.*)\]\ .*\}, \{.*\}'
kernel_cs_rexp='.*callstack_kernel\ \=\ \[(.*)\]\ .*\}, \{.*\}'

def main():
    """
        Reads a line from stdin and expect it to be a wellformed Babeltrace CLI
        output containing containing a callstack context of the domain passed
        as argument.
    """
    expected_callstack = set()
    recorded_callstack = set()
    cs_type=None

    if len(sys.argv) <= 2:
        print(sys.argv)
        raise ValueError('USAGE: ./{} (--kernel|--user EXE) FUNC-NAMES'.format(sys.argv[0]))

    # If the `--user` option is passed, save the next argument as the path
    # to the executable
    argc=1
    executable=None
    if sys.argv[argc] in '--kernel':
        rexp = kernel_cs_rexp
        cs_type='kernel'
    elif sys.argv[argc] in '--user':
        rexp = user_cs_rexp
        cs_type='user'
        argc+=1
        executable = sys.argv[argc]
    else:
        raise Exception('Unknown domain')

    argc+=1

    # Extract the function names that are expected to be found call stack of
    # the current events
    for func in sys.argv[argc:]:
        expected_callstack.add(func)

    # Read the tested line for STDIN
    event_line = None
    for line in sys.stdin:
        event_line = line
        break

    # Extract the userspace callstack context of the event
    m = re.match(rexp, event_line)

    # If there is no match, exit with error
    if m is None:
        raise re.error('Callstack not found in event line')
    else:
        raw_callstack = str(m.group(1))
        if cs_type in 'user':
            recorded_callstack=extract_user_func_names(executable, raw_callstack)
        elif cs_type in 'kernel':
            recorded_callstack=extract_kernel_func_names(raw_callstack)
        else:
            raise Exception('Unknown domain')

    # Verify that all expected function are present in the callstack
    for e in expected_callstack:
        if e not in recorded_callstack:
            raise Exception('Expected function name not found in recorded callstack')

    sys.exit(0)

if __name__ == '__main__':
    main()
