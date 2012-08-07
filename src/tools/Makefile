default: probe

test: probe
	@make clean
	@make
	@./probe /var/lib/libvirt/images/ubuntu-ext4.img

probe:
	@clang probe.c \
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
	@rm probe

test_tail:
	@python ./tail.py \
		localhost \
		'$(shell hostname):tinycore:/mnt/sda1/tce/blargh'
