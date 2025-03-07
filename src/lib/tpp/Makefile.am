plugindir = "$(lttnglibdir)"
plugin_LTLIBRARIES =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA =

plugin_LTLIBRARIES += libtpp-client.la
libtpp_client_la_SOURCES = \
	client.hpp \
	client.cpp
libtpp_client_la_CXXFLAGS = $(AM_CXXFLAGS) $(UST_CFLAGS)
libtpp_client_la_LIBADD = $(UST_LIBS)
libtpp_client_la_LDFLAGS = $(AM_LDFLAGS) $(FORCE_SHARED_LIB_OPTIONS)
pkgconfig_DATA += lttng-tpp-client.pc

plugin_LTLIBRARIES += libtpp-common.la
libtpp_common_la_SOURCES = \
	common.hpp \
	common.cpp
libtpp_common_la_CXXFLAGS = $(AM_CXXFLAGS) $(UST_CFLAGS)
libtpp_common_la_LIBADD = $(UST_LIBS)
libtpp_common_la_LDFLAGS = $(AM_LDFLAGS) $(FORCE_SHARED_LIB_OPTIONS)
pkgconfig_DATA += lttng-tpp-common.pc
