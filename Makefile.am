ACLOCAL_AMFLAGS = -I m4

DIST_SUBDIRS = include src extras doc tests

SUBDIRS = include src doc tests

if BUILD_EXTRAS
SUBDIRS += extras
endif

dist_doc_DATA = LICENSE \
                ChangeLog \
		README.md

dist_noinst_DATA = CodingStyle

EXTRA_DIST = extras/lttng-bash_completion gpl-2.0.txt lgpl-2.1.txt
