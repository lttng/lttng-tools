# SPDX-License-Identifier: GPL-2.0-only

ACLOCAL_AMFLAGS = -I m4

include $(top_srcdir)/aminclude_static.am

clean-local: code-coverage-clean
distclean-local: code-coverage-dist-clean

# `doc/examples` is placed last since it requires artifact from `src` and
# `src` can require artifact from `doc` (--enable-embedded-help).
SUBDIRS = include doc src tests doc/examples

if BUILD_EXTRAS
SUBDIRS += extras
endif

dist_doc_DATA = LICENSE \
                ChangeLog \
		README.adoc

dist_noinst_DATA = CodingStyle.md

TEST_DEPS = \
	.shellcheckrc

EXTRA_DIST = extras/lttng-bash_completion \
	     extras/zsh-completion \
	     LICENSES/BSD-2-Clause \
	     LICENSES/BSD-3-Clause \
	     LICENSES/GPL-2.0 \
	     LICENSES/LGPL-2.1 \
	     LICENSES/MIT \
	     LICENSES/BSL-1.0 \
	     version \
	     $(TEST_DEPS)

# Copy files required by the test suite to the build directory
all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(TEST_DEPS); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(TEST_DEPS); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
