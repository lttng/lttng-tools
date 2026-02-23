# SPDX-FileCopyrightText: 2026 EfficiOS Inc.
#
# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = msgpack fmt

EXTRA_DIST = \
	mint.hpp \
	nlohmann/json.hpp \
	optional.hpp \
	REUSE.toml

noinst_LTLIBRARIES =

# libargpar
noinst_LTLIBRARIES += argpar/libargpar.la
argpar_libargpar_la_SOURCES = \
	argpar/argpar.c \
	argpar/argpar.h \
	argpar/argpar.hpp
