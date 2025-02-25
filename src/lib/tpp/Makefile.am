plugindir = "$(lttnglibdir)"

plugin_LTLIBRARIES = libtpp-common.la

libtpp_common_la_SOURCES = \
	common.hpp \
	common.cpp
libtpp_common_la_CXXFLAGS = $(AM_CXXFLAGS) $(UST_CFLAGS)
libtpp_common_la_LIBADD = $(UST_LIBS)
libtpp_common_la_LDFLAGS = $(AM_LDFLAGS) $(FORCE_SHARED_LIB_OPTIONS)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = lttng-tpp-common.pc
