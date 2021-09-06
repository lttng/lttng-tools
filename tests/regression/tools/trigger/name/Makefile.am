# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la
LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

noinst_PROGRAMS = trigger_name
# This test explicitly tests APIs that were marked as deprecated.
trigger_name_CXXFLAGS = -Wno-deprecated-declarations $(AM_CXXFLAGS)
trigger_name_SOURCES = trigger_name.cpp
trigger_name_LDADD = $(LIBTAP) $(LIBLTTNG_CTL)

noinst_SCRIPTS = test_trigger_name_backwards_compat
EXTRA_DIST = test_trigger_name_backwards_compat

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
