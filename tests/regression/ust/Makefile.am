if HAVE_LIBLTTNG_UST_CTL
SUBDIRS = nprocesses high-throughput low-throughput before-after multi-session \
		overlap buffers-pid linking daemon exit-fast fork libc-wrapper \
		periodical-metadata-flush java-jul java-log4j python-logging \
		getcpu-override clock-override type-declarations \
		rotation-destroy-flush blocking

if HAVE_OBJCOPY
SUBDIRS += baddr-statedump ust-dl
endif

EXTRA_DIST = test_event_basic test_event_tracef test_event_perf

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
