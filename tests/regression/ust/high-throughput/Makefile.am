# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(srcdir)

# Disable some warnings flags to accomodate the tracepoint headers
AM_CFLAGS += \
	-Wno-redundant-decls

noinst_PROGRAMS = gen-events
gen_events_SOURCES = main.c tp.c tp.h
gen_events_LDADD = $(UST_LIBS) $(DL_LIBS)

noinst_SCRIPTS = test_high_throughput.py \
	test_high_throughput_snapshot.py
EXTRA_DIST = test_high_throughput.py \
	test_high_throughput_snapshot.py

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
