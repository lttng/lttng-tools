SUBDIRS = utils regression unit

if USE_PYTHON
check-am:
	./run.sh unit_tests
	./run.sh fast_regression
	./run.sh with_bindings_regression
else
check-am:
	./run.sh unit_tests
	./run.sh fast_regression
endif

dist_noinst_SCRIPTS = run.sh unit_tests fast_regression long_regression root_regression with_bindings_regression
EXTRA_DIST = run.sh unit_tests fast_regression long_regression root_regression with_bindings_regression
