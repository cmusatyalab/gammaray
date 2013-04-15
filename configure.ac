#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([gammaray], [1.0], [wolf@cs.cmu.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/datastructures/bitarray.c])
AC_CONFIG_HEADERS([src/common/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries.
AC_CHECK_LIB([hiredis], [redisConnect])

# Initialize libtool
LT_INIT

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h locale.h stddef.h stdint.h stdlib.h
                  string.h sys/time.h unistd.h wchar.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_blksize])
AC_STRUCT_ST_BLOCKS
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# lib substitutions
AC_SUBST([LIBGAMMARAY_SO_VERSION, [0:0:0]])
AC_SUBST([LIBGAMMARAY_API_VERSION], [1.0])

# Checks for library functions.
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([gethostname gettimeofday memmove memset setlocale])

AC_OUTPUT
