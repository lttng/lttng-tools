# SPDX-FileCopyrightText: 2026 EfficiOS Inc.
#
# SPDX-License-Identifier: GPL-2.0-only

JAVAROOT = .

noinst_SCRIPTS = test_java_log4j JTestLTTngLog4j.java
EXTRA_DIST = test_java_log4j JTestLTTngLog4j.java

if TEST_JAVA_LOG4J_AGENT
dist_noinst_JAVA = JTestLTTngLog4j.java
endif # TEST_JAVA_LOG4J_AGENT

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

