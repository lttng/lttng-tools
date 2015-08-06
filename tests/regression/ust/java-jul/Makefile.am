JAVAROOT = .

noinst_SCRIPTS = test_java_jul JTestLTTng.java
EXTRA_DIST = test_java_jul JTestLTTng.java

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

