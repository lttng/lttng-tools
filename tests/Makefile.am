# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS =

if BUILD_TESTS
SUBDIRS += . utils meta unit regression stress destructive perf
if HAVE_PGREP
check-am:
	$(top_srcdir)/tests/utils/warn_processes.sh $(PGREP)
endif
else
	@echo "========================================="
	@echo "WARNING: Tests were disabled at configure"
	@echo "========================================="
endif


EXTRA_DIST = README.adoc

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
