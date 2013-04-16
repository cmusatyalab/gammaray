###############################################################################
# Makefile.am                                                                 #
#                                                                             #
# This is the automake template for the gammaray project.                     #
#                                                                             #
#                                                                             #
#   Authors: Wolfgang Richter <wolf@cs.cmu.edu>                               #
#                                                                             #
#                                                                             #
#   Copyright 2013 Carnegie Mellon University                                 #
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

#setup 
ACLOCAL_AMFLAGS = -I build-aux/m4
AM_CFLAGS = -I$(srcdir)/src/include

# distribution
EXTRA_DIST = LICENSE NOTICE README src/include/*.h

# helper libraries
noinst_LTLIBRARIES = libbitarray.la libbson.la libcolor.la libredis.la \
					 libutil.la libmbr.la libext4.la libntfs.la \
					 libqemucommon.la

libcolor_la_SOURCES = src/util/color.c
libutil_la_SOURCES = src/util/util.c
libbitarray_la_SOURCES = src/datastructures/bitarray.c
libbitarray_la_LIBADD = libcolor.la libutil.la
libbson_la_SOURCES = src/bson/bson-encoder.c \
					 src/bson/bson-decoder.c \
					 src/bson/bson-util.c
libbson_la_LIBADD = libcolor.la libutil.la
libredis_la_SOURCES = src/inference_engine/redis_queue.c
libredis_la_LIBADD = libbitarray.la libutil.la
libredis_la_CFLAGS = $(AM_CFLAGS) -I/usr/include/hiredis
libmbr_la_SOURCES = src/disk_crawler/mbr/mbr.c
libext4_la_SOURCES = src/disk_crawler/ext4/ext4.c
libntfs_la_SOURCES = src/disk_crawler/ntfs/ntfs.c
libqemucommon_la_SOURCES = src/inference_engine/qemu_common.c
libqemucommon_la_LIBADD = libbson.la

# binaries
bin_PROGRAMS = bitarray_test bson_printer bson_test async_queuer \
			   inference_engine disk_crawler
bindir = $(srcdir)/bin

bitarray_test_SOURCES = src/datastructures/bitarray_test.c
bitarray_test_LDADD = libutil.la libcolor.la libbitarray.la

bson_printer_SOURCES = src/bson/bson_printer.c
bson_printer_LDADD = libbson.la libcolor.la

bson_test_SOURCES = src/bson/bson_test.c
bson_test_LDADD = libbson.la

async_queuer_SOURCES = src/inference_engine/async_queuer.c
async_queuer_LDADD = libbitarray.la libcolor.la libredis.la \
					 libutil.la libqemucommon.la -lpthread

inference_engine_SOURCES = src/inference_engine/inference_engine.c \
						   src/inference_engine/deep_inspection.c
inference_engine_LDADD = libbitarray.la libcolor.la libredis.la \
						 libutil.la libqemucommon.la libext4.la \
						 libntfs.la -lpthread

disk_crawler_SOURCES = src/disk_crawler/disk_crawler.c
disk_crawler_LDADD = libbitarray.la libbson.la libcolor.la libutil.la \
					 libmbr.la libext4.la libntfs.la
