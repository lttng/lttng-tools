# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = event_name field_stats

AM_CPPFLAGS += -I$(srcdir)
AM_CXXFLAGS += $(babeltrace2_CFLAGS) \
	$(WARN_FLAGS)

noinst_LTLIBRARIES = lttngtest.la

# lttng-tools uses -fvisibility=hidden by default, but to
# produce a loadable plugin some of the symbols must not be
# hidden. Override the `-fvisibility` for this shared object.
lttngtest_la_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-fvisibility=default

lttngtest_la_SOURCES = \
	lttngtest-plugin.cpp \
	fmt.hpp \
	utils.hpp

lttngtest_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(LD_NO_UNDEFINED) \
	$(top_builddir)/src/vendor/fmt/libfmt.la \
	-rpath / -avoid-version -module $(LD_NOTEXT)

lttngtest_la_LIBADD = \
	event_name/event_name.la \
	field_stats/field_stats.la
