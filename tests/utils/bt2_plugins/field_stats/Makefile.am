# SPDX-License-Identifier: GPL-2.0-only

AM_CXXFLAGS += $(babeltrace2_CFLAGS) \
	$(WARN_FLAGS)

noinst_LTLIBRARIES = field_stats.la
field_stats_la_SOURCES = \
	field_stats.cpp \
	field_stats.hpp
field_stats_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LD_NO_UNDEFINED) \
	-avoid-version -module $(LD_NOTEXT)
