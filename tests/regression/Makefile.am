SUBDIRS = tools kernel ust

EXTRA_DIST = run-report.py test_list.py

if HAVE_LIBLTTNG_UST_CTL
SUBDIRS += ust
endif # HAVE_LIBLTTNG_UST_CTL

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
