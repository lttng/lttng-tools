#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# Generator script for many event classes test application

import argparse
import os
import sys


def get_license_header(license_type="GPL-2.0-only"):
    """Generate a license header for generated files."""
    if license_type == "MIT":
        return """\
/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Generated file
 */

"""
    else:  # GPL-2.0-only
        return """\
/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Generated file
 */

"""


def generate_instrumentation_headers(output_dir, num_events, event_source_count):
    for i in range(event_source_count):
        generate_instrumentation_h(output_dir, num_events, "_{}".format(i))


def generate_instrumentation_h(output_dir, num_events, suffix=""):
    """Generate the instrumentation.h header file with tracepoint definitions."""

    header = get_license_header("MIT")
    header += """\
#undef LTTNG_UST_TRACEPOINT_PROVIDER
#define LTTNG_UST_TRACEPOINT_PROVIDER many_events{0}

#undef LTTNG_UST_TRACEPOINT_INCLUDE
#define LTTNG_UST_TRACEPOINT_INCLUDE "instrumentation{0}.h"

#if !defined(_INSTRUMENTATION{0}_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _INSTRUMENTATION{0}_H

#include <lttng/tracepoint.h>
#include <stdint.h>

""".format(
        suffix
    )

    # Generate tracepoint events
    events = []
    for i in range(num_events):
        event = """\
TRACEPOINT_EVENT(many_events{1}, event_{0},
\tTP_ARGS(int, value),
\tTP_FIELDS(
\t\tctf_integer(int, field, value)
\t)
)

""".format(
            i, suffix
        )
        events.append(event)

    footer = """\
#endif /* _INSTRUMENTATION{0}_H */

/* This part must be outside ifdef protection */
#include <lttng/tracepoint-event.h>
""".format(
        suffix
    )

    content = header + "".join(events) + footer

    output_path = os.path.join(output_dir, "instrumentation{0}.h".format(suffix))
    with open(output_path, "w") as f:
        f.write(content)


def generate_instrumentation_sources(output_dir, event_sources_count):
    for i in range(event_sources_count):
        generate_instrumentation_c(output_dir, "_{}".format(i))


def generate_instrumentation_c(output_dir, suffix=""):
    """Generate the instrumentation.c implementation file."""

    content = get_license_header()
    content += """\
#define LTTNG_UST_TRACEPOINT_CREATE_PROBES
#define LTTNG_UST_TRACEPOINT_DEFINE
#include "instrumentation{0}.h"
""".format(
        suffix
    )

    output_path = os.path.join(output_dir, "instrumentation{0}.c".format(suffix))
    with open(output_path, "w") as f:
        f.write(content)


def generate_emit_events_h(output_dir):
    """Generate the emit-events.h header file."""

    content = get_license_header()
    content += """\
#ifndef _EMIT_EVENTS_H
#define _EMIT_EVENTS_H

#ifdef __cplusplus
extern "C" {
#endif

void emit_all_events(void);
void emit_one_event(void);

#ifdef __cplusplus
}
#endif
#endif /* _EMIT_EVENTS_H */
"""

    output_path = os.path.join(output_dir, "emit-events.h")
    with open(output_path, "w") as f:
        f.write(content)


def generate_emit_events_c(output_dir, num_events, event_source_count):
    """Generate the emit-events.c implementation file."""

    content = get_license_header()
    content += """\
#include "emit-events.h"
"""
    for i in range(event_source_count):
        content += """\
#include "instrumentation{0}.h"
""".format(
            "_{}".format(i)
        )
    content += """\
void emit_all_events(void)
{
"""

    # Generate tracepoint calls
    for n in range(event_source_count):
        for i in range(num_events):
            content += "\ttracepoint(many_events_{1}, event_{0}, {0});\n".format(i, n)

    content += """\
}

"""
    content += """\
void emit_one_event(void)
{
\ttracepoint(many_events_0, event_0, 0);
}
"""

    output_path = os.path.join(output_dir, "emit-events.c")
    with open(output_path, "w") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(
        description="Generate C source files with many tracepoints"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        required=True,
        help="Output directory for generated files",
    )
    parser.add_argument(
        "--event-class-count",
        type=int,
        default=10,
        help="Number of tracepoint event classes to generate per event source (default: 10)",
    )
    parser.add_argument(
        "--event-source-count",
        type=int,
        default=1,
        help="The number of tracepoint event sources to generate (default: 1)",
    )

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)

    # Generate instrumentation files
    generate_instrumentation_headers(
        args.output_dir, args.event_class_count, args.event_source_count
    )
    generate_instrumentation_sources(args.output_dir, args.event_source_count)
    generate_emit_events_h(args.output_dir)
    generate_emit_events_c(
        args.output_dir, args.event_class_count, args.event_source_count
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
