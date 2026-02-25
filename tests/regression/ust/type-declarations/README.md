<!--
SPDX-FileCopyrightText: 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Type declarations test

This test checks if tracepoints using type declarations work correctly.

## DESCRIPTION


This test launches a process which generates events with fields using type
declarations.

The test makes sure the events are present and the fields have all the
correct data.

## DEPENDENCIES

To run this test, you will need:

  - lttng-tools (with python bindings)
  - babeltrace
  - python 3.0 or better
