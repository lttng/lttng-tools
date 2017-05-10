AM_CPPFLAGS += -I$(srcdir)

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-tracef
gen_ust_tracef_SOURCES = gen-ust-tracef.c
gen_ust_tracef_LDADD = -llttng-ust $(DL_LIBS)
endif
