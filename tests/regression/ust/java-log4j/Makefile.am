
noinst_SCRIPTS = test_java_log4j JTestLTTng.java
EXTRA_DIST = test_java_log4j JTestLTTng.java

if HAVE_JAVA_JDK
JCC=$(JAVA_JDK)/bin/javac
else
JCC=javac
endif

# We still need to copy static files for out of tree and dist build
if BUILD_JAVA_LOG4J_AGENT
all-local: static_file JTestLTTng.class

%.class: %.java
	$(JCC) -d "$(builddir)" $(JAVACFLAGS) $<
else
all-local: static_file
endif # BUILD_JAVA_LOG4J_AGENT

JTestLTTng.class: JTestLTTng.java

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

