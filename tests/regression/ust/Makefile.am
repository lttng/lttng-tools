if HAVE_LIBLTTNG_UST_CTL
SUBDIRS = nprocesses high-throughput low-throughput before-after multi-session \
		overlap buffers-uid linking daemon exit-fast fork libc-wrapper \
		periodical-metadata-flush

EXTRA_DIST = test_event_basic test_event_wildcard

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

endif
