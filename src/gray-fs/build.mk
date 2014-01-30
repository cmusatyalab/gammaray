bin_PROGRAMS += bin/gray-fs

bin_gray_fs_SOURCES = src/gray-fs/gray-fs.c
bin_gray_fs_LDADD   = $(libdir)/libbitarray.la \
					  $(libdir)/libcolor.la \
					  $(libdir)/libqemucommon.la \
					  $(libdir)/libredis.la \
					  $(libdir)/libutil.la \
					  -lfuse \
					  -lpthread \
					  -ldl
