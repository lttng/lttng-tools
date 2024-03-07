# SPDX-License-Identifier: GPL-2.0-only

noinst_SCRIPTS = __init__.py \
	test_ust_constructor_c_dynamic.py \
	test_ust_constructor_c_static.py \
	test_ust_constructor_cpp_dynamic.py \
	test_ust_constructor_cpp_static.py \
	ust_constructor_common.py

EXTRA_DIST = __init__.py \
	test_ust_constructor_c_dynamic.py \
	test_ust_constructor_c_static.py \
	test_ust_constructor_cpp_dynamic.py \
	test_ust_constructor_cpp_static.py \
	ust_constructor_common.py


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
