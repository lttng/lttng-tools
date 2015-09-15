noinst_SCRIPTS = test_save test_load
EXTRA_DIST = $(noinst_SCRIPTS) load-42.lttng load-42-complex.lttng \
	load-42-trackers.lttng

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
