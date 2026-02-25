<!--
SPDX-FileCopyrightText: 2014-2017 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

Build lttng-tools with "-DVALGRIND" to create executables compatible
with the valgrind tool. The start with e.g.:

```
valgrind --leak-check=full lttng-sessiond
```

If you want to track memory allocations and accesses within
lttng-sessiond children processes (e.g. lttng-consumerd) as well:

```
valgrind --leak-check=full --trace-children=yes lttng-sessiond
```
