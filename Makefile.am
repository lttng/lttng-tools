ACLOCAL_AMFLAGS = -I config

SUBDIRS = src/common/ \
		  benchmark \
		  src \
		  tests \
		  include \
		  doc

dist_doc_DATA = LICENSE \
                ChangeLog

EXTRA_DIST = extras/lttng-bash_completion

bench:
	./benchmark/runall.sh
