if BUILD_JAVA_LOG4J_AGENT

noinst_SCRIPTS = test_java_log4j JTestLTTng.java
EXTRA_DIST = test_java_log4j JTestLTTng.java

if HAVE_JAVA_JDK
JCC=$(JAVA_JDK)/bin/javac
else
JCC=javac
endif

all-local: JTestLTTng.class

%.class: %.java
	$(JCC) -d "$(builddir)" $(JAVACFLAGS) $<

JTestLTTng.class: JTestLTTng.java

all-local:
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

endif # BUILD_JAVA_LOG4J_AGENT
