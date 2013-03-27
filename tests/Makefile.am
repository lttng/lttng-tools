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
