# SPDX-License-Identifier: GPL-2.0-only

JAVAROOT = .

noinst_SCRIPTS = \
	test_agent_log4j2_domain_log4j

EXTRA_DIST = \
	JTestLTTngLog4j2.java \
	domain-log4j.xml \
	test_agent_log4j2_domain_log4j

if TEST_JAVA_LOG4J2_AGENT
dist_noinst_JAVA = JTestLTTngLog4j2.java
endif # TEST_JAVA_LOG4J2_AGENT

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
