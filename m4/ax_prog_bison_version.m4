# SPDX-License-Identifier: FSFAP
#
# ===========================================================================
#   https://www.gnu.org/software/autoconf-archive/ax_prog_bison_version.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PROG_BISON_VERSION([VERSION],[ACTION-IF-TRUE],[ACTION-IF-FALSE])
#
# DESCRIPTION
#
#   Makes sure that bison version is greater or equal to the version
#   indicated. If true the shell commands in ACTION-IF-TRUE are executed. If
#   not the shell commands in commands in ACTION-IF-TRUE are executed. If
#   not the shell commands in ACTION-IF-FALSE are run. Note if $YACC is not
#   set (for example by running AC_PROG_YACC or AC_PATH_PROG) the macro
#   will fail.
#
#   Example:
#
#     AC_PROG_YACC
#     AX_PROG_BISON_VERSION([3.0.2],[ ... ],[ ... ])
#
#   This will check to make sure that the bison you have is at least version
#   3.0.2 or greater.
#
#   NOTE: This macro uses the $YACC variable to perform the check, if it's
#   empty it will failover to the $BISON variable for backwards compatibility.
#
# LICENSE
#
#   Copyright (c) 2015 Jonathan Rajotte-Julien <jonathan.rajotte-julien@efficios.com>
#                 2017 Michael Jeanson <mjeanson@efficios.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 4

AC_DEFUN([AX_PROG_BISON_VERSION],[
    AC_REQUIRE([AC_PROG_SED])
    AC_REQUIRE([AC_PROG_GREP])

     AS_IF([test -z "$YACC"],[
         AS_IF([test -n "$BISON"],[
             YACC=$BISON
         ])
     ])

    AS_IF([test -n "$YACC"],[
        ax_bison_version="$1"

        AC_MSG_CHECKING([for bison version])
        changequote(<<,>>)
        bison_version=`$YACC --version 2>&1 \
          | $SED -n -e '/bison (GNU Bison)/b inspect
b
: inspect
s/.* (\{0,1\}\([0-9]*\.[0-9]*\.[0-9]*\))\{0,1\}.*/\1/;p'`
        changequote([,])
        AC_MSG_RESULT($bison_version)

	AC_SUBST([BISON_VERSION],[$bison_version])

        AX_COMPARE_VERSION([$bison_version],[ge],[$ax_bison_version],[
	    :
            $2
        ],[
	    :
            $3
        ])
    ],[
        AC_MSG_WARN([could not find bison])
        $3
    ])
])
