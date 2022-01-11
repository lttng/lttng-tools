# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la
LIBCOMMON_GPL=$(top_builddir)/src/common/libcommon-gpl.la

noinst_PROGRAMS = ini_config
EXTRA_DIST = test_ini_config sample.ini

ini_config_SOURCES = ini_config.cpp
ini_config_LDADD = $(LIBTAP) $(LIBCOMMON_GPL)

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
