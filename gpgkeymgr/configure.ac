#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.66])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AC_CONFIG_SRCDIR([gpgkeymgr.cpp])
#AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
#AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([gpgme], [gpgme_new])

# Checks for header files.
AC_CHECK_HEADERS([libintl.h locale.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([mkdir setlocale])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
