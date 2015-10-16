SUBDIRS =
DIST_SUBDIRS = utils regression unit stress

if BUILD_TESTS
SUBDIRS += utils regression unit stress
endif

installcheck-am:
if BUILD_TESTS
	./run.sh unit_tests
	./run.sh fast_regression
if PYTHON_BINDING
	./run.sh with_bindings_regression
endif
else
	@echo "========================================="
	@echo "WARNING: Tests were disabled at configure"
	@echo "========================================="
endif

check-am:
if BUILD_TESTS
	./run.sh unit_tests
	./run.sh fast_regression
if PYTHON_BINDING
	./run.sh with_bindings_regression
endif
else
	@echo "========================================="
	@echo "WARNING: Tests were disabled at configure"
	@echo "========================================="
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
