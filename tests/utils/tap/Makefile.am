noinst_LTLIBRARIES = libtap.la
libtap_la_SOURCES = tap.c tap.h
dist_noinst_SCRIPTS = tap.sh
EXTRA_DIST = tap.sh

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
