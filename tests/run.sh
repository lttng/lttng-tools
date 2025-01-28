#!/bin/bash
#
# SPDX-FileCopyrightText: 2013 Christian Babeux <christian.babeux@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only
#

[ -z "$1" ] && echo "Error: No testlist. Please specify a testlist to run." && exit 1

prove --merge --exec '' - < "$1"
