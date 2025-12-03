#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2025 Philippe Proulx <pproulx@efficios.com>
# SPDX-License-Identifier: LGPL-2.1-only

import json
import sys


def extract_prop(metadata_path, fragment_type, prop_path):
    if metadata_path == "-":
        content = sys.stdin.buffer.read()
    else:
        with open(metadata_path, "rb") as f:
            content = f.read()

    # Split fragments (one per JSON Text Sequence item)
    fragments = content.split(b"\x1e")
    values = []

    for fragment in fragments:
        fragment = fragment.strip()

        if not fragment:
            continue

        obj = json.loads(fragment)

        if obj.get("type") != fragment_type:
            # Not what we're looking for
            continue

        # Navigate the property path
        value = obj

        for key in prop_path.split("/"):
            if isinstance(value, dict):
                value = value.get(key)
            elif isinstance(value, list) and key.isdigit():
                value = value[int(key)]
            else:
                value = None
                break

            if value is None:
                break

        if value is not None:
            values.append(value)

    return values


def _main():
    if len(sys.argv) != 4:
        print(
            "Usage: {} METADATA-PATH FRAGMENT-TYPE PROP-PATH".format(sys.argv[0]),
            file=sys.stderr,
        )
        sys.exit(1)

    values = extract_prop(sys.argv[1], sys.argv[2], sys.argv[3])

    if not values:
        sys.exit(1)

    for value in values:
        print(value)


if __name__ == "__main__":
    _main()
