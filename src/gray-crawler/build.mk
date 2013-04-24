bin_PROGRAMS       += bin/gray-crawler
noinst_LTLIBRARIES += lib/libext4.la \
					  lib/libmbr.la \
					  lib/libntfs.la


lib_libext4_la_SOURCES = src/gray-crawler/ext4/ext4.c
lib_libntfs_la_SOURCES = src/gray-crawler/ntfs/ntfs.c
lib_libmbr_la_SOURCES  = src/gray-crawler/mbr/mbr.c

bin_gray_crawler_SOURCES = src/gray-crawler/gray-crawler.c
bin_gray_crawler_LDADD   = $(libdir)/libbitarray.la \
						   $(libdir)/libbson.la \
						   $(libdir)/libcolor.la \
						   $(libdir)/libext4.la \
						   $(libdir)/libmbr.la \
						   $(libdir)/libntfs.la \
						   $(libdir)/libutil.la
