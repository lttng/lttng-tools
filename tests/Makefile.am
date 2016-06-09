SUBDIRS =
DIST_SUBDIRS = utils regression unit stress destructive

if BUILD_TESTS
SUBDIRS += . utils regression unit stress destructive
if HAS_PGREP
check-am:
	$(top_srcdir)/tests/utils/warn_processes.sh $(PGREP)
endif
else
	@echo "========================================="
	@echo "WARNING: Tests were disabled at configure"
	@echo "========================================="
endif


dist_noinst_SCRIPTS = run.sh fast_regression long_regression root_regression root_destructive_tests
EXTRA_DIST = run.sh fast_regression long_regression root_regression README root_destructive_tests

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
