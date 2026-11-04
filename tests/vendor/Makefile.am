# SPDX-FileCopyrightText: Kienan Stewart <kstewart@efficios.com>
#
# SPDX-License-Identifier: GPL-2.0-only

EXTRA_DIST = ctypeslib2 \
	normand/normand.py \
	REUSE.toml

# Copy test scripts to the builddir for OOT builds
all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			if [ x"$$(dirname $$script)" != x"." ]; then \
				mkdir -p $(builddir)/$$(dirname $$script); \
			fi; \
			cp -f $(srcdir)/$$script $(builddir)/$$script; \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
