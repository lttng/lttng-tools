# SYNOPSIS
#
#   LTTNG_CHECK_SDT_WORKS([ACTION-SUCCESS], [ACTION-FAILURE])
#
# DESCRIPTION
#
#   Check whether it's possible to build a binary with Systemtap SDT probes.
#
#   ACTION-SUCCESS/ACTION-FAILURE are shell commands to execute on
#   success/failure.
#
# LICENSE
#
#   Copyright (c) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
#   Copyright (c) 2019 Michael Jeanson <mjeanson@efficios.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved.  This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([LTTNG_CHECK_SDT_WORKS], [
  AC_CACHE_CHECK([whether SDT probes compile], [lttng_cv_sdt_works], [
    AC_COMPILE_IFELSE([
      AC_LANG_SOURCE([[
	#define SDT_USE_VARIADIC
	#include <sys/sdt.h>
	void fct(void)
	{
		STAP_PROBEV(provider,name,1,2,3,4,5,6,7,8,9,10);
	}
      ]])
    ], [
      lttng_cv_sdt_works=yes
    ], [
      lttng_cv_sdt_works=no
    ])
  ])
  AS_IF([test "x$lttng_cv_sdt_works" = "xyes"], [
    m4_default([$1], :)
  ], [
    m4_default([$2], :)
  ])
])
