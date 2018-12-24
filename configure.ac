# tpcap configure.ac


# Project Information
AC_INIT([tpcap], [0.0], [xxx@xxx])


# General definitions
AC_CONFIG_MACRO_DIR([build])


# General automake options.
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])


# Check for dependencies (C++, AR, Lex, Yacc and Make)
AC_PROG_CXX
AM_PROG_AR
AC_PROG_MAKE_SET


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string])
AC_CHECK_HEADERS([iostream])
AC_CHECK_HEADERS([sys/utsname.h])


# ??
LT_INIT([dlopen])

# Identify platform
AC_CANONICAL_HOST


# Variables to be used inside the Makefile.am files.
MSC_BASE_DIR=`pwd`
AC_SUBST([MSC_BASE_DIR])


AC_SUBST(GLOBAL_LDADD)
AC_SUBST(GLOBAL_CPPFLAGS)


GLOBAL_CFLAGS=""
AC_SUBST(GLOBAL_CFLAGS)


# Files to be generated via autotools.
AC_CONFIG_FILES([\
    Makefile \
    src/Makefile \
	test/Makefile
    ])


AC_CONFIG_HEADERS([src/config.h])

# Debug
AC_ARG_ENABLE(debug,
    [AC_HELP_STRING([--enable-debug],[Turn on the debug])],

    [case "${enableval}" in
        yes) debugState=true ;;
        no)  debugState=false ;;
        *) AC_MSG_ERROR(bad value ${enableval} for --enable-afl-fuzz) ;;
    esac],

    [debugState=false]
    )

if test "$debugState" != "true"; then
    TPCAP_NO_DEBUG="-DNO_DEBUG=1"
    AC_SUBST(TPCAP_NO_DEBUG)
fi

# make check-valgrind
AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_CHECK

# Generate the files.
AC_OUTPUT

echo " "
echo "Options"
if test $debugState = true; then
    echo "   + TpcapDebug                                   ....enabled"
else
    echo "   + TpcapDebug                                   ....disabled"
fi
