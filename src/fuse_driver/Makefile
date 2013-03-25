default:
	@clang -Wall \
		   -Werror \
		   xray_fs.c \
		   ../stream_analyzer/redis_queue.c \
		   ../stream_analyzer/deep_inspection.c \
		   ../disk_analyzer/ext4/ext4.c \
		   ../disk_analyzer/ntfs/ntfs.c \
		   ../util/color.c \
		   ../util/util.c \
		   ../bson/bson-encoder.c \
		   ../bson/bson-decoder.c \
		   ../datastructures/bitarray.c \
		   -g \
		   -o xray_fs \
		   -lhiredis \
		   -I../disk_analyzer/ext4 \
		   -I../disk_analyzer/ext2 \
		   -I../disk_analyzer/ntfs \
		   -I../disk_analyzer/mbr \
		   -I../util \
		   -I../bson \
		   -I../datastructures \
		   -I../stream_analyzer \
		   -I/usr/include/hiredis \
		   `pkg-config fuse --cflags --libs` \
		   -lm

test: default
	@mkdir -p /tmp/test
	@./xray_fs -d -s /tmp/test /home/wolf/VM/vm_ext4_test/vm_ext4_test.raw

clean:
	@rm xray_fs
