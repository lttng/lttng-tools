#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only

LD_PRELOAD="liblttng-ust-dl.so" LD_LIBRARY_PATH=. ./prog
