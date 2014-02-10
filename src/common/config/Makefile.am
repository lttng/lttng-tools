AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src

noinst_LTLIBRARIES = libconfig.la

libconfig_la_SOURCES = ini.c ini.h config.c config.h
libconfig_la_CPPFLAGS = $(XML_CPPFLAGS)
libconfig_la_LIBADD = $(XML_LIBS)

xmldir = $(datadir)/xml/lttng
xml_DATA = session.xsd
dist_xml_DATA = session.xsd
