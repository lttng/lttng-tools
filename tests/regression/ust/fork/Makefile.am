# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir)

# Disable some warnings flags to accomodate the tracepoint headers
AM_CFLAGS += \
	-Wno-redundant-decls

noinst_PROGRAMS = fork fork2
fork_SOURCES = fork.c ust_tests_fork.h
fork_LDADD = $(UST_LIBS) -llttng-ust-fork $(DL_LIBS)

fork2_SOURCES = fork2.c
fork2_LDADD = $(UST_LIBS) -llttng-ust-fork $(DL_LIBS)

noinst_SCRIPTS = test_fork.py
EXTRA_DIST = test_fork.py

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
