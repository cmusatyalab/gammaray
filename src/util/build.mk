#noinst_LTLIBRARIES += $(libdir)/libcolor.la $(libdir)/libutil.la
noinst_LTLIBRARIES += lib/libcolor.la lib/libutil.la

utilsrc = $(srcdir)/src/util

lib_libcolor_la_SOURCES = $(utilsrc)/color.c
lib_libutil_la_SOURCES = $(utilsrc)/util.c
