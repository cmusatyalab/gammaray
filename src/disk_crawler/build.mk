noinst_LTLIBRARIES += lib/libmbr.la lib/libext4.la \
					  lib/libntfs.la

bin_PROGRAMS += bin/disk_crawler

disksrc = $(srcdir)/src/disk_crawler

lib_libmbr_la_SOURCES = $(disksrc)/mbr/mbr.c
lib_libext4_la_SOURCES = $(disksrc)/ext4/ext4.c
lib_libntfs_la_SOURCES = $(disksrc)/ntfs/ntfs.c

bin_disk_crawler_SOURCES = $(disksrc)/disk_crawler.c
bin_disk_crawler_LDADD = $(libdir)/libbitarray.la $(libdir)/libbson.la \
						 $(libdir)/libcolor.la $(libdir)/libutil.la \
						 $(libdir)/libmbr.la $(libdir)/libext4.la \
						 $(libdir)/libntfs.la
