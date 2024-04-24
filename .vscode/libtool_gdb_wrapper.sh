#!/usr/bin/env sh
# Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# Wrapper script to setup the environment before invoking gdb
# on the in-tree binaries (under `.libs`)

libtool --mode=execute gdb "$@"
