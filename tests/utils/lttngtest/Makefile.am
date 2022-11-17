# SPDX-License-Identifier: GPL-2.0-only

EXTRA_DIST = __init__.py \
	environment.py \
	logger.py \
	lttngctl.py \
	lttng.py \
	tap_generator.py

dist_noinst_SCRIPTS = __init__.py \
	environment.py \
	logger.py \
	lttngctl.py \
	lttng.py \
	tap_generator.py

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
