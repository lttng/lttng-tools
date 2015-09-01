SUBDIRS = utils regression unit stress

installcheck-am:
if HAS_PGREP
	./warn_lttng_processes.sh $(PGREP)
endif
	./run.sh unit_tests
	./run.sh fast_regression
if PYTHON_BINDING
	./run.sh with_bindings_regression
endif

check-am:
if HAS_PGREP
	./warn_lttng_processes.sh $(PGREP)
endif
	./run.sh unit_tests
	./run.sh fast_regression
if PYTHON_BINDING
	./run.sh with_bindings_regression
endif

dist_noinst_SCRIPTS = run.sh unit_tests fast_regression long_regression root_regression with_bindings_regression
EXTRA_DIST = run.sh unit_tests fast_regression long_regression root_regression with_bindings_regression README

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
