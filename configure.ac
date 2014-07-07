###############################################################################
# configure.ac                                                                #
#                                                                             #
# This is the autoconf template for the gammaray project.                     #
#                                                                             #
#                                                                             #
#   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                               #
#                                                                             #
#                                                                             #
#   Copyright 2013-2014 Carnegie Mellon University                            #
#                                                                             #
#   Licensed under the Apache License, Version 2.0 (the "License");           #
#   you may not use this file except in compliance with the License.          #
#   You may obtain a copy of the License at                                   #
#                                                                             #
#       http://www.apache.org/licenses/LICENSE-2.0                            #
#                                                                             #
#   Unless required by applicable law or agreed to in writing, software       #
#   distributed under the License is distributed on an "AS IS" BASIS,         #
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  #
#   See the License for the specific language governing permissions and       #
#   limitations under the License.                                            #
###############################################################################
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([gammaray], [1.0], [wolf@cs.cmu.edu])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])
AM_INIT_AUTOMAKE([1.11 foreign subdir-objects -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/datastructures/bitarray.c])
AC_CONFIG_HEADERS([src/common/config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
AM_PROG_AR

# Checks for libraries.
AC_CHECK_LIB([hiredis], [redisConnect],,
             AC_MSG_FAILURE([could not find libhiredis]))
AC_CHECK_LIB([event], [event_base_new],,
             AC_MSG_FAILURE([could not find libevent]))

# Initialize libtool
LT_INIT([disable-shared])

# lib substitutions
AC_SUBST([LIBGAMMARAY_SO_VERSION], [0:0:0])
AC_SUBST([LIBGAMMARAY_API_VERSION], [1.0])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
