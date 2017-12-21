noinst_SCRIPTS = test_kernel test_kernel_streaming test_ust_fast test_ust_long ust_test test_ust_streaming
EXTRA_DIST = test_kernel test_kernel_streaming test_ust_fast test_ust_long ust_test test_ust_streaming

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
