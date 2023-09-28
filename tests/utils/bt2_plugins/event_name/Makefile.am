# SPDX-License-Identifier: GPL-2.0-only

AM_CXXFLAGS += $(babeltrace2_CFLAGS) \
	$(WARN_FLAGS)

noinst_LTLIBRARIES = event_name.la
event_name_la_SOURCES = \
	event_name.cpp \
	event_name.hpp
event_name_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LD_NO_UNDEFINED) \
	-avoid-version -module $(LD_NOTEXT)
