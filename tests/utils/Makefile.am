# SPDX-License-Identifier: GPL-2.0-only

# Build the local dir first, llibtestutils.la is used by testapps
SUBDIRS = . testapp

EXTRA_DIST = \
	lttngtest/environment.py \
	lttngtest/__init__.py \
	lttngtest/logger.py \
	lttngtest/lttngctl.py \
	lttngtest/lttng.py \
	lttngtest/tap_generator.py \
	parse-callstack.py \
	tap-driver.sh \
	tap/tap.sh \
	utils.sh \
	warn_processes.sh

noinst_HEADERS = \
	xml-utils/common.hpp

noinst_LTLIBRARIES = \
	bt2_plugins/lttngtest.la \
	libtestutils.la \
	tap/libtap.la

noinst_PROGRAMS = \
	tap/clock \
	xml-utils/extract_xml \
	xml-utils/pretty_xml \
	xml-utils/validate_xml

libtestutils_la_SOURCES = \
	utils.cpp \
	utils.h


## tap

tap_clock_SOURCES = tap/clock.cpp
tap_clock_LDADD = \
	libtestutils.la \
	$(top_builddir)/src/vendor/fmt/libfmt.la

tap_libtap_la_SOURCES = tap/tap.c tap/tap.h
tap_libtap_la_LIBADD = libtestutils.la


## xml-utils

xml_utils_validate_xml_SOURCES = xml-utils/validate_xml.cpp
xml_utils_validate_xml_CPPFLAGS = $(libxml2_CFLAGS) $(AM_CPPFLAGS)
xml_utils_validate_xml_LDADD = $(libxml2_LIBS)

xml_utils_extract_xml_SOURCES = xml-utils/extract_xml.cpp
xml_utils_extract_xml_CPPFLAGS = $(libxml2_CFLAGS) $(AM_CPPFLAGS)
xml_utils_extract_xml_LDADD = $(libxml2_LIBS)

xml_utils_pretty_xml_SOURCES = xml-utils/pretty_xml.cpp
xml_utils_pretty_xml_CPPFLAGS = $(libxml2_CFLAGS) $(AM_CPPFLAGS)
xml_utils_pretty_xml_LDADD = $(libxml2_LIBS)


## bt2_plugins

bt2_plugins_lttngtest_la_SOURCES = \
	bt2_plugins/event_name/event_name.cpp \
	bt2_plugins/event_name/event_name.hpp \
	bt2_plugins/field_stats/field_stats.cpp \
	bt2_plugins/field_stats/field_stats.hpp \
	bt2_plugins/fmt.hpp \
	bt2_plugins/lttngtest-plugin.cpp \
	bt2_plugins/utils.hpp

# lttng-tools uses -fvisibility=hidden by default, but to
# produce a loadable plugin some of the symbols must not be
# hidden. Override the `-fvisibility` for this shared object.
bt2_plugins_lttngtest_la_CXXFLAGS = \
	$(AM_CXXFLAGS) \
	-fvisibility=default

bt2_plugins_lttngtest_la_CPPFLAGS = \
	$(babeltrace2_CFLAGS) \
	$(AM_CPPFLAGS)

bt2_plugins_lttngtest_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	-rpath / -avoid-version -module

bt2_plugins_lttngtest_la_LIBADD = \
	$(top_builddir)/src/vendor/fmt/libfmt.la


# Copy test scripts to the builddir for OOT builds
all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			if [ x"$$(dirname $$script)" != x"." ]; then \
				mkdir -p $(builddir)/$$(dirname $$script); \
			fi; \
			cp -f $(srcdir)/$$script $(builddir)/$$script; \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
