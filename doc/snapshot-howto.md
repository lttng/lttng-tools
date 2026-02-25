<!--
SPDX-FileCopyrightText: 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# LTTng Flight Recorder Snapshot HOWTO

Mathieu Desnoyers
July 21st, 2013

This document presents how to use the snapshot feature of LTTng.

Snapshots allow to grab the content of flight recorder tracing buffers
at the time the snapshot record command is invoked. Flight recorder
tracing gather trace data in memory, overwriting the oldest information,
without requiring any disk I/O. The snapshot record command exports the
snapshot to the destination specified by the user.

Basic usage:

Session daemon started as root for kernel tracing:

```
lttng-sessiond -d
```

From a user part of the tracing group (for kernel tracing):

```
$ lttng create --snapshot
$ lttng enable-event -k -a      # enable kernel tracing
$ lttng enable-event -u -a      # enable user-space tracing
$ lttng start

    [ do something, generate activity on the system ]

$ lttng snapshot record

    [ do more stuff... ]

$ lttng snapshot record

$ lttng stop
$ lttng destroy
```

Each "lttng snapshot" command records a snapshot of the current buffer
state. "lttng enable --snapshot" automatically setups the buffers in
overwrite mode for flight recording, and does not attach any output file
to the trace. The "lttng snapshot record" command can be performed
either while tracing is started or stopped.

As an example, this generates the following hierarchy under the
directory reported by the "create" command above:

```
.
├── snapshot-1-20130721-141838-0
│   ├── kernel
│   │   ├── channel0_0
│   │   ├── channel0_1
│   │   ├── channel0_2
│   │   ├── channel0_3
│   │   └── metadata
│   └── ust
│       └── uid
│           └── 1000
│               └── 64-bit
│                   ├── channel0_0
│                   ├── channel0_1
│                   ├── channel0_2
│                   ├── channel0_3
│                   └── metadata
└── snapshot-1-20130721-141842-1
    ├── kernel
    │   ├── channel0_0
    │   ├── channel0_1
    │   ├── channel0_2
    │   ├── channel0_3
    │   └── metadata
    └── ust
        └── uid
            └── 1000
                └── 64-bit
                    ├── channel0_0
                    ├── channel0_1
                    ├── channel0_2
                    ├── channel0_3
                    └── metadata
```


Then, running babeltrace on, e.g.

```
babeltrace snapshot-1-20130721-141838-0
```

shows the content of the first snapshot.

Please refer to the lttng(1) manpage for details on the snapshot mode.
