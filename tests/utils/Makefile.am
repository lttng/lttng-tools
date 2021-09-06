# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = . tap testapp xml-utils

EXTRA_DIST = utils.sh test_utils.py babelstats.pl warn_processes.sh \
             parse-callstack.py
dist_noinst_SCRIPTS = utils.sh test_utils.py babelstats.pl tap-driver.sh
noinst_LTLIBRARIES = libtestutils.la

libtestutils_la_SOURCES = \
	utils.cpp \
	utils.h

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
