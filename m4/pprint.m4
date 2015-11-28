# Pretty printing macros.
#
# Author: Philippe Proulx <pproulx@efficios.com>

# PPRINT_INIT(): initializes the pretty printing system.
#
# Use this macro before any other PPRINT_* macro.
AC_DEFUN([PPRINT_INIT], [
  PPRINT_YES_MSG=yes
  PPRINT_NO_MSG=no
  PPRINT_CONFIG_TS=50
  PPRINT_CONFIG_INDENT=2

  AS_IF([test -x "/bin/tput"], [
    AS_IF([test -n "$PS1" -a `/bin/tput colors` -ge 8 -a -t 1], [
      # interactive shell and colors supported and standard output
      # file descriptor is opened on a terminal
      PPRINT_COLOR_TXTBLK=`tput setf 0`
      PPRINT_COLOR_TXTBLU=`tput setf 1`
      PPRINT_COLOR_TXTGRN=`tput setf 2`
      PPRINT_COLOR_TXTCYN=`tput setf 3`
      PPRINT_COLOR_TXTRED=`tput setf 4`
      PPRINT_COLOR_TXTPUR=`tput setf 5`
      PPRINT_COLOR_TXTYLW=`tput setf 6`
      PPRINT_COLOR_TXTWHT=`tput setf 7`
      PPRINT_COLOR_BLD=`tput bold`
      PPRINT_COLOR_BLDBLK=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTBLK
      PPRINT_COLOR_BLDBLU=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTBLU
      PPRINT_COLOR_BLDGRN=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTGRN
      PPRINT_COLOR_BLDCYN=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTCYN
      PPRINT_COLOR_BLDRED=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTRED
      PPRINT_COLOR_BLDPUR=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTPUR
      PPRINT_COLOR_BLDYLW=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTYLW
      PPRINT_COLOR_BLDWHT=$PPRINT_COLOR_BLD$PPRINT_COLOR_TXTWHT
      PPRINT_COLOR_RST=`tput sgr0`

      # colored yes and no
      PPRINT_YES_MSG="${PPRINT_COLOR_BLDGRN}$PPRINT_YES_MSG$PPRINT_COLOR_RST"
      PPRINT_NO_MSG="${PPRINT_COLOR_BLDRED}$PPRINT_NO_MSG$PPRINT_COLOR_RST"

      # subtitle color
      PPRINT_COLOR_SUBTITLE=$PPRINT_COLOR_BLDCYN
    ])
  ])
])

# PPRINT_SUBTITLE(subtitle): pretty prints a subtitle.
#
# Use PPRINT_INIT() before using this macro.
AC_DEFUN([PPRINT_SUBTITLE], [
  subtitle="$1"
  AS_ECHO("$PPRINT_COLOR_SUBTITLE$subtitle$PPRINT_COLOR_RST")
])

# PPRINT_PROP_STRING(title, value, title_color?): pretty prints a
# string property.
#
# The $PPRINT_CONFIG_TS variable must be set to the desired number
# of characters from the beginning of the line after which the value
# is printed.
#
# The $PPRINT_CONFIG_INDENT variable must be set to the desired indentation
# level.
#
# Use PPRINT_INIT() before using this macro.
AC_DEFUN([PPRINT_PROP_STRING], [
  pprint_indent=$PPRINT_CONFIG_INDENT
  pprint_title="$1"
  pprint_value="$2"

  AS_IF([test $# -ge 3], [
    pprint_title_color="$3"
  ], [
    pprint_title_color=""
  ])

  pprint_title_len=`expr length "$pprint_title"`
  pprint_ts=$PPRINT_CONFIG_TS
  pprint_spaces=`expr $pprint_ts - $pprint_title_len - $pprint_indent - 1`

  AS_IF([test $pprint_spaces -le 0], [pprint_spaces=1])

  # This is probably more portable than using printf or awk.
  for i in `seq $pprint_indent`; do
    AS_ECHO_N(" ")
  done

  AS_ECHO_N("$pprint_title_color$pprint_title$PPRINT_COLOR_RST:")

  for i in `seq $pprint_spaces`; do
    AS_ECHO_N(" ")
  done

  AS_ECHO("$PPRINT_COLOR_BLD$pprint_value$PPRINT_COLOR_RST")
])

# PPRINT_PROP_BOOL(title, value, title_color?): pretty prints a boolean
# property.
#
# The value must be 0 (false) or 1 (true).
#
# Uses the PPRINT_PROP_STRING() with the "yes" or "no" string.
AC_DEFUN([PPRINT_PROP_BOOL], [
  pprint_title="$1"
  pprint_value="$2"

  test $pprint_value -eq 0 && pprint_msg="$PPRINT_NO_MSG" || pprint_msg="$PPRINT_YES_MSG"

  AS_IF([test $# -ge 3], [
    pprint_title_color="$3"
    PPRINT_PROP_STRING("$pprint_title", "$pprint_msg", "$pprint_title_color")
  ], [
    pprint_title_color=""
    PPRINT_PROP_STRING("$pprint_title", "$pprint_msg")
  ])
])

# PPRINT_WARN(msg): pretty prints a warning message.
#
# The $PPRINT_CONFIG_INDENT variable must be set to the desired indentation
# level.
#
# Use PPRINT_INIT() before using this macro.
AC_DEFUN([PPRINT_WARN], [
  pprint_msg="$1"
  pprint_indent=$PPRINT_CONFIG_INDENT

  for i in `seq $pprint_indent`; do
    AS_ECHO_N(" ")
  done

  AS_ECHO("${PPRINT_COLOR_TXTYLW}WARNING:$PPRINT_COLOR_RST $PPRINT_COLOR_BLDYLW$pprint_msg$PPRINT_COLOR_RST")
])

# PPRINT_ERROR(msg): pretty prints an error message and exits.
#
# Use PPRINT_INIT() before using this macro.
AC_DEFUN([PPRINT_ERROR], [
  pprint_msg="$1"
  AC_MSG_ERROR("$PPRINT_COLOR_BLDRED$pprint_msg$PPRINT_COLOR_RST")
])
