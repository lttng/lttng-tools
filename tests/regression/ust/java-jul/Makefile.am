# SPDX-License-Identifier: GPL-2.0-only

JAVAROOT = .

noinst_SCRIPTS = test_java_jul \
	JTestLTTng.java \
	test_ust_app_ctl_path_separators.sh
EXTRA_DIST = test_java_jul \
	JTestLTTng.java \
	test_ust_app_ctl_path_separators.sh

if TEST_JAVA_JUL_AGENT
dist_noinst_JAVA = JTestLTTng.java
endif # TEST_JAVA_JUL_AGENT

all-local: static_file

static_file:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	rm -f *.class
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi

