
		../bson/bson-encoder.c \
		../disk_analyzer/ebr.c \
		../disk_analyzer/ext2.c \
		../disk_analyzer/mbr.c \
		../util/color.c \
		../util/util.c \
		-I../disk_analyzer/ \
		-I../util/ \
		-I../bson/ \
		-o probe\
		-Wall\
		-Werror

clean:

test_tail:
	@python ./tail.py \
		localhost \
		'$(shell hostname):tinycore:/mnt/sda1/tce/blargh'
