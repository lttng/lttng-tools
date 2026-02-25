<!--
SPDX-FileCopyrightText: 2018 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>

SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Extra version patches

This directory and its content is used to generate the
**EXTRA_VERSION_PATCHES** constant used in `include/version.i`.

A third party can create a file inside this directory and its name will be
propagated in all "version" output of the following lttng-executable:
    lttng-relayd
    lttng-sessiond
    lttng
