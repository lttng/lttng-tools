# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir)

# Disable some warnings flags to accomodate the tracepoint headers
AM_CFLAGS += \
	-Wno-redundant-decls

noinst_PROGRAMS = type-declarations
type_declarations_SOURCES = type-declarations.c ust_tests_td.h
type_declarations_LDADD = $(UST_LIBS) $(DL_LIBS)
type_declarations_CPPFLAGS = $(UST_CFLAGS) $(DL_CFLAGS) $(AM_CPPFLAGS)

noinst_SCRIPTS = test_type_declarations.py
EXTRA_DIST = test_type_declarations.py

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
