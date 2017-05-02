noinst_LTLIBRARIES = libconfig.la

libconfig_la_SOURCES = ini.c ini.h session-config.c session-config.h \
		config-session-abi.h config-internal.h
libconfig_la_CPPFLAGS = $(libxml2_CFLAGS) $(AM_CPPFLAGS)
libconfig_la_LIBADD = ${libxml2_LIBS}

xmldir = $(datadir)/xml/lttng
dist_xml_DATA = session.xsd
EXTRA_DIST = session.xsd

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
