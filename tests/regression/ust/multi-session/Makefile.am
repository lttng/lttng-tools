# SPDX-License-Identifier: GPL-2.0-only

AM_CFLAGS += -I$(srcdir)

# Disable some warnings flags to accomodate the tracepoint headers
AM_CFLAGS += \
	-Wno-redundant-decls

noinst_PROGRAMS = gen-nevents
gen_nevents_SOURCES = gen-nevents.c tp.c ust_gen_nevents.h
gen_nevents_LDADD = $(UST_LIBS) $(DL_LIBS)

noinst_SCRIPTS = test_multi_session
EXTRA_DIST = test_multi_session

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
